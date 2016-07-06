"""
This module calls the AWS ListMetrics() API followed by multiple calls to
GetMetricStatistics() to get metrics from AWS.

A dictionary configured by the 'metrics' key in the configuration file is
used to determine which metrics should lead to a call to GetMetricStatistics().

Each metric value returned from GetMetricStatistics() is sent to the Wavefront
proxy on port 2878 (or other port if configured differently).  Point tags
are picked up from the Dimensions.  Source is determined by searching
the point tags for a list of "accepted" source locations
(e.g., 'Service', 'LoadBalancerName', etc).

The last run time is stored in a configuration file in
/opt/wavefront/etc/aws-metrics.conf and will be used on the next run to
determine the appropriate start time.  If no configuration file is found,
the start time is determined by subtracting the delay_minutes from the
current time.
"""

import ConfigParser
import datetime
import io
import json
import numbers
import os
import os.path
import re
import time
import zipfile

import logging.config

import boto3
import dateutil

from wavefront.metrics_writer import WavefrontMetricsWriter
from wavefront.utils import Configuration
from wavefront import command
from wavefront import utils

# Configuration for metrics that should be retrieved is contained in this
# configuration in a "metrics" key.  This is a dictionary
# where the key is a regular expression and the value is an object with keys:
#    * stats
#        a list of statistics to pull down with the GetMetricStatistics() call.
#        valid values are any of : 'Average', 'Maximum', 'Minimum', "SampleCount', 'Sum'
#    * source_names
#        an array of :
#          - tag names (Dimensions)
#          - Dimensions array index (0 based)
#          - String literals
#        The first match is returned as the source name.
#
# The key to the dictionary is a regular expression that should match a:
#     <namespace>.<metric_name> (lower case with /=>.)
#
DEFAULT_METRIC_CONFIG_FILE = './aws-metrics.json.conf'

# default configuration
DEFAULT_CONFIG_FILE = '/opt/wavefront/etc/aws-metrics.conf'

# Mapping for statistic name to its "short" name.  The short name is used
# in the metric name sent to Wavefront
STAT_SHORT_NAMES = {
    'Average': 'avg',
    'Minimum': 'min',
    'Maximum': 'max',
    'Sum': 'sum',
    'SampleCount': 'count'
}

# The directory where we should look for and store the cache
# files of instances and their tags.
CACHE_DIR = '/tmp'

# characters to replace in the operation when creating the metric name
SPECIAL_CHARS_REPLACE_MAP = {
    '/': '-',
    ':': '-'
}

#pylint: disable=too-few-public-methods
class AwsBillingConfiguration(object):
    """
    Configuration for billing
    """
    def __init__(self, config):
        super(AwsBillingConfiguration, self).__init__()

        self.config = config
        self.enabled = self.config.getboolean('aws_billing', 'enabled', False)
        self.role_arn = self.config.get('aws_billing', 'role_arn', None)
        self.role_external_id = self.config.get(
            'aws_billing', 'external_id', None)
        self.billing_thread_names = self.config.getlist(
            'aws_billing', 'billing_threads', [])

        self.billing_threads = []
        for name in self.billing_thread_names:
            section = 'billing-' + name
            self.billing_threads.append(
                AwsBillingDetailThreadConfiguration(config, section))

#pylint: disable=too-many-instance-attributes
class AwsCloudwatchConfiguration(object):
    """
    Configuration for Cloudwatch
    """

    def __init__(self, config, region):
        super(AwsCloudwatchConfiguration, self).__init__()

        self.config = config
        self.section_name = 'cloudwatch_' + region
        default_section_name = 'cloudwatch'

        self.enabled = self.config.getboolean(
            self.section_name, 'enabled', False, default_section_name)
        self.workers = int(self.config.get(
            self.section_name, 'workers', 1, default_section_name))
        self.has_suffix_for_single_stat = self.config.getboolean(
            self.section_name, 'single_stat_has_suffix', True,
            default_section_name)
        self.default_delay_minutes = int(self.config.get(
            self.section_name, 'first_run_start_minutes', 5,
            default_section_name))
        self.namespace = self.config.get(
            self.section_name, 'namespace', 'aws', default_section_name)
        self.ec2_tag_keys = self.config.getlist(
            self.section_name, 'ec2_tag_keys', [], default_section_name)
        self.metric_config_path = self.config.get(
            self.section_name, 'metric_config_path', DEFAULT_METRIC_CONFIG_FILE,
            default_section_name)

        self.start_time = self.config.getdate(
            self.section_name, 'start_time', None, default_section_name)
        self.end_time = self.config.getdate(
            self.section_name, 'end_time', None, default_section_name)
        self.last_run_time = self.config.getdate(
            self.section_name, 'last_run_time', None, default_section_name)
        self.update_start_end_times()

        self.namespaces = set()
        self.metrics_config = None

    def update_start_end_times(self):
        """
        Updates start/end times after last_run_time set
        """

        utcnow = (datetime.datetime.utcnow()
                  .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        delta = datetime.timedelta(minutes=self.default_delay_minutes)
        if self.last_run_time:
            if not self.start_time or self.last_run_time > self.start_time:
                self.start_time = self.last_run_time - delta
                self.end_time = utcnow
        elif not self.start_time:
            self.start_time = utcnow - delta
            self.end_time = utcnow

    def set_last_run_time(self, run_time):
        """
        Sets the last run time to the run_time argument.

        Arguments:
        run_time - the time when this script last executed successfully (end)
        """

        if utils.CANCEL_WORKERS_EVENT.is_set():
            return

        utcnow = (datetime.datetime.utcnow()
                  .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        if not run_time:
            run_time = utcnow

        self.config.set(
            self.section_name, 'last_run_time', run_time.isoformat())
        self.config.save()
        self.last_run_time = run_time

    def validate(self):
        """
        Validates configuration
        """
        if not self.metric_config_path:
            raise ValueError('options.metric_config_path is required')
        if not os.path.exists(self.metric_config_path):
            raise ValueError('ERROR: Configuration file (%s) does not exist' %
                             (self.metric_config_path))

    def load_metric_config(self):
        """
        Loads the metric configuration from the configuration file.
        """

        if self.metrics_config:
            return
        with open(self.metric_config_path, 'r') as conffd:
            config = json.load(conffd)

        if 'metrics' not in config:
            raise ValueError('ERROR: Configuration file (%s) is not valid' %
                             (self.metric_config_path))

        self.metrics_config = config['metrics']
        for _, config in self.metrics_config.iteritems():
            if 'namespace' in config and config['namespace']:
                self.namespaces.add(config['namespace'])

    #pylint: disable=unsupported-membership-test
    #pylint: disable=unsubscriptable-object
    def get_metric_config(self, namespace, metric_name):
        """
        Given a namespace and metric, get the configuration.

        Arguments:
        namespace - the namespace
        metric_name - the metric's name

        Returns:
        the configuration for this namespace and metric
        """

        self.load_metric_config()
        current_match = None
        metric = namespace.replace('/', '.').lower() + '.' + metric_name.lower()
        for name, config in self.metrics_config.iteritems():
            if re.match(name, metric, re.IGNORECASE):
                if current_match is None or \
                   ('priority' in current_match and \
                    current_match['priority'] < config['priority']):
                    current_match = config

        return current_match

#pylint: disable=too-few-public-methods
#pylint: disable=too-many-instance-attributes
class AwsBillingDetailThreadConfiguration(object):
    """
    Configuration for a billing detail section in the configuration file
    """

    def __init__(self, config, section_name):
        super(AwsBillingDetailThreadConfiguration, self).__init__()

        self.config = config
        self.section_name = section_name
        self.namespace = self.config.get(section_name, 'namespace', None)
        self.enabled = self.config.getboolean(section_name, 'enabled', False)
        self.region = self.config.get(section_name, 's3_region', None)
        self.bucket = self.config.get(section_name, 's3_bucket', None)
        self.prefix = self.config.get(section_name, 's3_prefix', None)
        self.header_row_index = int(
            self.config.get(section_name, 'header_row_index', 1))
        self.dimensions = self._build_table(
            self.config.getlist(section_name, 'dimension_column_names', []))
        self.metrics = self._build_table(
            self.config.getlist(section_name, 'metric_column_names', []))
        self.source_names = self.config.getlist(section_name, 'source_names', [])
        self.dates = self._build_table(
            self.config.getlist(section_name, 'date_column_names', []), '|')
        self.duration = self.config.getlist(section_name, 'duration_column_names', [])
        self.instance_id_columns = self.config.getlist(
            section_name, 'instance_id_column_names', [])
        self.delay = int(self.config.get(section_name, 'delay', 3600))
        self.last_run_time = self.config.getdate(
            section_name, 'last_run_time', None)
        self.user_point_tags = self.config.getboolean(
            section_name, 'user_point_tags', False)
        self.record_id_column = self.config.get(
            section_name, 'record_id_column_name', None)
        self.maximum_number_of_rows = int(self.config.get(
            section_name, 'maximum_number_of_rows', 0))
        self.sleep_after_rows = int(self.config.get(
            section_name, 'sleep_after_rows', 0))
        self.sleep_ms = float(self.config.get(
            section_name, 'sleep_ms', 0.0)) / 1000

    @staticmethod
    def _build_table(lst, delimiter=':'):
        """
        Build a dictionary from a list of delimiter-separated key-value pairs
        Arguments:
        lst - list of strings
        Returns:
        dictionary
        """

        rtn = {}
        if lst:
            for item in lst:
                parts = item.split(delimiter)
                if len(parts) == 1:
                    rtn[parts[0]] = parts[0]
                elif len(parts) == 2:
                    rtn[parts[0]] = parts[1]

        return rtn

    def set_last_run_time(self, run_time):
        """
        Sets the last run time to the run_time argument.

        Arguments:
        run_time - the time when billing last executed successfully (end)
        """

        if utils.CANCEL_WORKERS_EVENT.is_set():
            return

        utcnow = (datetime.datetime.utcnow()
                  .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        if not run_time:
            run_time = utcnow
        self.last_run_time = run_time
        self.config.set(
            self.section_name, 'last_run_time', run_time.isoformat())
        self.config.save()

    def get_last_record_id(self, curr_month):
        """
        Gets the last record id for the given month
        """
        return self.config.get(
            self.section_name, 'last_record_id_' + curr_month, None)

    def set_last_record_id(self, curr_month, record_id):
        """
        Sets the last record id read

        Arguments:
        record_id - last record id
        """

        if not record_id:
            return

        self.config.set(
            self.section_name, 'last_record_id_' + curr_month, record_id)
        self.config.save()

class AwsSubAccountConfiguration(object):
    """
    Configuration for a specific sub account section in the INI file
    """

    def __init__(self, config, section_name):
        super(AwsSubAccountConfiguration, self).__init__()

        self.config = config
        self.enabled = self.config.getboolean(section_name, 'enabled', False)
        self.role_arn = self.config.get(section_name, 'role_arn', None)
        self.role_external_id = self.config.get(section_name, 'external_id', None)
        self.access_key_id = self.config.get(section_name, 'access_key_id', None)
        self.secret_access_key = self.config.get(
            section_name, 'secret_access_key', None)

class AwsMetricsCommand(command.Command):
    """
    Abstract base class for both AWS cloudwatch metrics and AWS billing metrics
    commands.
    """

    def __init__(self, **kwargs):
        super(AwsMetricsCommand, self).__init__(**kwargs)
        self.proxy = None
        self.config = None
        self.account = None

    def _init_proxy(self):
        """
        Initializes the proxy writer
        """

        self.proxy = WavefrontMetricsWriter(self.config.writer_host,
                                            self.config.writer_port,
                                            self.config.is_dry_run)
        self.proxy.start()

    def _init_logging(self):
        self.logger = logging.getLogger()

    def add_arguments(self, parser):
        """
        Adds arguments supported by this command to the argparse parser
        :param parser: the argparse parser created using .add_parser()
        """

        parser.add_argument('--config',
                            dest='config_file_path',
                            default=DEFAULT_CONFIG_FILE,
                            help='Path to configuration file')

    def _parse_args(self, arg):
        """
        Parses the arguments passed into this command.

        Arguments:
        arg - the argparse parser object returned from parser.parse_args()
        """

        self.config = AwsMetricsConfiguration(arg.config_file_path)
        self.config.validate()
        try:
            logging.config.fileConfig(arg.config_file_path)
        except ConfigParser.NoSectionError:
            pass

    #pylint: disable=no-self-use
    def get_help_text(self):
        """
        Returns help text for --help of this wavefront command
        """
        return "Pull metrics from AWS CloudWatch and push them into Wavefront"

    def _execute(self):
        """
        Execute this command
        """

        self._init_proxy()
        self.account = AwsAccount(self.config, True)

class AwsAccount(object):
    """
    Represents the AWS account and all of its sub accounts
    """

    def __init__(self, config, load=False):
        super(AwsAccount, self).__init__()
        self.config = config
        self.regions = self.config.regions
        self.sub_accounts = []
        self.sessions = {}
        if load:
            for sub_account in self.get_sub_accounts():
                sub_account.load_ec2_instance_data()

    def get_sub_accounts(self):
        """
        Gets a list of sub accounts
        """
        if not self.sub_accounts:
            for sub_account in self.config.sub_accounts:
                self.sub_accounts.append(AwsSubAccount(self, sub_account))
        return self.sub_accounts

    def get_account_id(self, role_arn=None):
        """
        Gets the account id by either parsing it from the role ARN or by
        getting the currently logged in user's ARN and parsing from there.
        """

        if role_arn:
            arn = role_arn

        else:
            iam_client = self.get_session('us-east-1', None, None).client('iam')
            arn = iam_client.get_user()['User']['Arn']

        return arn.split(':')[4]

    def get_session(self, region, role_arn, external_id, check_cache=True):
        """
        Creates a new session object in the given region
        Arguments:
        region - the region name
        check_cache - True to check the cache before creating new session
        """

        if role_arn:
            cache_key = ':'.join([region, role_arn, external_id])
        else:
            cache_key = region

        access_key_id = self.config.aws_access_key_id
        secret_access_key = self.config.aws_secret_access_key
        if not check_cache or cache_key not in self.sessions:
            if role_arn:
                session = boto3.session.Session()
                client = session.client(
                    'sts',
                    region_name=region,
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key)
                role = client.assume_role(RoleArn=role_arn,
                                          ExternalId=external_id,
                                          RoleSessionName='wavefront_session')
                self.sessions[cache_key] = boto3.Session(
                    role['Credentials']['AccessKeyId'],
                    role['Credentials']['SecretAccessKey'],
                    role['Credentials']['SessionToken'],
                    region_name=region)

            else:
                self.sessions[cache_key] = boto3.Session(
                    region_name=region,
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key)

        return self.sessions[cache_key]

class AwsSubAccount(object):
    """
    AWS sub-account
    """

    def __init__(self, parent, name):
        super(AwsSubAccount, self).__init__()

        self.parent_account = parent
        section_name = 'aws_sub_account_' + name
        self.sub_account_config = AwsSubAccountConfiguration(
            parent.config, section_name)

        self.instances = {}

    def get_account_id(self):
        """
        Gets the account id by either parsing it from the role ARN or by
        getting the currently logged in user's ARN and parsing from there.
        """

        return self.parent_account.get_account_id(
            self.sub_account_config.role_arn)

    def load_ec2_instance_data(self):
        """
        Loads all AWS EC2 instances and related tags in the account's regions
        Arguments:
        """

        for region in self.parent_account.regions:
            cloudwatch_config = (
                self.parent_account.config.get_cloudwatch_config(region))
            ec2_tag_keys = cloudwatch_config.ec2_tag_keys
            self.instances[region] = AwsInstances(
                self, region, ec2_tag_keys, True)

    def get_instances(self, region):
        """
        Gets the instances for the given region
        Arguments:
        region - the region name
        Returns:
        AwsInstances object for the given region or None
        """

        if region in self.instances:
            return self.instances[region]
        else:
            return None

    def get_session(self, region, check_cache=True):
        """
        Creates a new session object in the given region
        Arguments:
        region - the region name
        check_cache - True to check the cache before creating new session
        """

        return self.parent_account.get_session(
            region, self.sub_account_config.role_arn,
            self.sub_account_config.role_external_id, check_cache)

#pylint: disable=too-many-instance-attributes
class AwsMetricsConfiguration(Configuration):
    """
    Configuration file for this command
    """

    def __init__(self, config_file_path):
        super(AwsMetricsConfiguration, self).__init__(
            config_file_path=config_file_path)

        self.writer_host = self.get('writer', 'host', '127.0.0.1')
        self.writer_port = int(self.get('writer', 'port', '2878'))
        self.is_dry_run = self.getboolean('writer', 'dry_run', True)

        self.delay = int(self.get('options', 'delay', 300))

        self.aws_access_key_id = self.get('aws', 'access_key_id', None)
        self.aws_secret_access_key = self.get('aws', 'secret_access_key', None)
        self.regions = self.getlist('aws', 'regions', None, None, ',', True)
        self.sub_accounts = self.getlist('aws', 'sub_accounts', [])
        self.cloudwatch = {}
        for region in self.regions:
            self.cloudwatch[region] = AwsCloudwatchConfiguration(self, region)

    def get_cloudwatch_config(self, region):
        """
        Gets the configuration for cloudwatch for the given region
        Arguments:
        region - the name of the region
        """

        if region in self.cloudwatch:
            return self.cloudwatch[region]
        else:
            return None

    def validate(self):
        """
        Checks that all required configuration items are set
        Throws:
        ValueError when a configuration item is missing a value
        """

        if (not self.aws_access_key_id or
                not self.aws_secret_access_key or
                not self.regions):
            raise ValueError('AWS access key ID, secret access key, '
                             'and regions are required')

        for _, cloudwatch in self.cloudwatch.iteritems():
            cloudwatch.validate()

class AwsInstances(object):
    """
    Queries and caches the tags of all instances in a region.  Results are
    cached in a configured directory.  Cached results are used if the
    date of the file is within the last day (using modified time).
    The configuration object stores the AWS tag keys to retrieve from each
    instance.  If this configuration is not set (blank or null), this
    class does nothing.
    """
    def __init__(self, sub_account, region, ec2_tag_keys, load_now=False):
        """
        Initializes the class.
        Arguments:
        sub_account -
        region - the region name
        ec2_tag_keys - array of tag key names
        load_now -
        """

        super(AwsInstances, self).__init__()
        self.sub_account = sub_account
        self.region = region
        self.ec2_tag_keys = ec2_tag_keys
        self.instances = None
        if load_now:
            self.load()

    def _get_cache_file_path(self):
        """
        Generates a file path for the given account
        Arguments:
        sub_account - the account
        """
        fname = ('instance_tag_%s_cache_%s.json' %
                 (self.sub_account.get_account_id(), self.region, ))
        return os.path.join(CACHE_DIR, fname)

    def _query_instance_tags(self):
        """
        Calls EC2.DescribeInstances() and retrieves all instances and their tags
        """

        self.instances = {}

        _instances = (self.sub_account.get_session(self.region)
                      .resource('ec2').instances.all())
        for instance in _instances:
            tags = {}

            # hard-coded instance attributes (data coming from instance object)
            if 'instanceType' in self.ec2_tag_keys:
                tags['instanceType'] = instance.instance_type
            if 'imageId' in self.ec2_tag_keys:
                tags['imageId'] = instance.instance_type
            if 'publicDnsName' in self.ec2_tag_keys:
                tags['publicDnsName'] = instance.public_dns_name
            if 'privateDnsName' in self.ec2_tag_keys:
                tags['privateDnsName'] = instance.private_dns_name
            if 'vpcId' in self.ec2_tag_keys:
                tags['vpcId'] = instance.vpc_id
            if 'architecture' in self.ec2_tag_keys:
                tags['architecture'] = instance.architecture

            # tags coming from the EC2 tags
            if instance.tags:
                for tag in instance.tags:
                    if (self.ec2_tag_keys[0] == '*' or
                            tag['Key'] in self.ec2_tag_keys):
                        tags[tag['Key']] = tag['Value']

            # store the tags in the dictionary
            self.instances[instance.id] = tags

        # store the results on disk for next time
        with open(self._get_cache_file_path(), 'w') as cachefd:
            json.dump(self.instances, cachefd)

    def _load_instance_tags_from_cache(self):
        """
        Loads the tags from the cache file if it exists.
        Returns:
        True - when data loaded from cache; False - o/w
        """

        path = self._get_cache_file_path()
        if os.path.exists(path):
            now = datetime.datetime.utcnow()
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            time_to_refresh = mtime + datetime.timedelta(days=1)
            if now > time_to_refresh:
                with open(path, 'r') as contents:
                    self.instances = json.load(contents)
                    return True

        return False

    def load(self):
        """
        Loads the instances and their tags.  Caches that data for at most one
        day (configurable?).
        """

        if self.instances or not self.ec2_tag_keys:
            return
        if not self._load_instance_tags_from_cache():
            self._query_instance_tags()

    def __contains__(self, item):
        if not self.instances:
            return False
        return item in self.instances
    def __getitem__(self, item):
        if not self.instances:
            return None
        return self.instances[item]

class AwsBillingMetricsCommand(AwsMetricsCommand):
    """
    Billing metrics command object.  Grabs metrics from billing CSV files.
    """

    def __init__(self, **kwargs):
        super(AwsBillingMetricsCommand, self).__init__(**kwargs)
        self.aws_billing_config = None

    def _execute(self):
        """
        Execute this command
        """

        super(AwsBillingMetricsCommand, self)._execute()
        self._process_billing()

    def _parse_args(self, arg):
        """
        Parses the arguments passed into this command.

        Arguments:
        arg - the argparse parser object returned from parser.parse_args()
        """

        super(AwsBillingMetricsCommand, self)._parse_args(arg)
        self.aws_billing_config = AwsBillingConfiguration(self.config)

    def _process_billing(self):
        """
        Processes the latest billing details CSV file.  A few helpful sites:
        http://www.dowdandassociates.com/products/cloud-billing/documentation/1.0/schema/
        http://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/detailed-billing-reports.html#reportstagsresources
        """

        utcnow = (datetime.datetime.utcnow()
                  .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))

        if utils.CANCEL_WORKERS_EVENT.is_set():
            return

        if not self.aws_billing_config.enabled:
            self.logger.info('Billing is disabled')
            return

        for config in self.aws_billing_config.billing_threads:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                break

            if config.enabled:
                if config.last_run_time:
                    diff = utcnow - config.last_run_time
                    if diff.total_seconds() <= config.delay:
                        self.logger.info('Not ready to run billing thread %s',
                                         config.section_name)
                        continue
                self._get_csv_from_s3(config)
                config.set_last_run_time(utcnow)
            else:
                self.logger.info('Billing thread %s is disabled',
                                 config.section_name)

    #pylint: disable=too-many-locals
    #pylint: disable=too-many-branches
    #pylint: disable=too-many-statements
    def _get_csv_from_s3(self, config):
        """
        Opens a CSV file that matches the prefix in the S3 bucket.
        Arguments:
        config - the AwsBillingDetailThreadConfiguration object
        """

        self.logger.info('Getting AWS billing details from S3 for %s',
                         config.section_name)
        utcnow = (datetime.datetime.utcnow()
                  .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))

        s3cli = self.account.get_session(
            config.region, self.aws_billing_config.role_arn,
            self.aws_billing_config.role_external_id).client('s3')
        acct_id = self.account.get_account_id(self.aws_billing_config.role_arn)
        curr_month = utcnow.strftime('%Y-%m')
        prefix = (config.prefix
                  .replace('${account_id}', acct_id)
                  .replace('${date}', curr_month))

        # find the item in the s3 bucket
        response = s3cli.list_objects(Bucket=config.bucket, Prefix=prefix)
        if (not response or 'Contents' not in response or
                not response['Contents']):
            self.logger.warning('Billing details file [%s] not found in %s\n%s',
                                prefix, config.bucket, str(response))
            return

        # open the item in S3
        key = None
        zipped = False
        for s3file in response['Contents']:
            if s3file['Key'][-8:] == '.csv.zip':
                key = s3file['Key']
                zipped = True
                break

            if s3file['Key'][-4:] == '.csv':
                key = s3file['Key']
                zipped = False

        if not key:
            self.logger.warning('Unable to find billing file [%s] in %s',
                                prefix, config.bucket)
            return

        response = s3cli.get_object(Bucket=config.bucket, Key=key)
        if not response or not response['Body']:
            self.logger.warning('Billing details file body not found')
            return

        contents = io.BytesIO(response['Body'].read())
        self.logger.info('Reading billing information from |%s|', key)
        if zipped:
            with zipfile.ZipFile(contents, 'r') as zipfd:
                csv_contents = io.BytesIO(zipfd.read(prefix + '.csv'))
                csv_file = utils.CsvFile(csv_contents, config.header_row_index)
                self.parse_csv(config, csv_file, curr_month)
        else:
            csv_file = utils.CsvFile(contents, config.header_row_index)
            self.parse_csv(config, csv_file, curr_month)

    def parse_csv(self, config, csvreader, curr_month):
        """
        Parse the CSV contents and generate metrics.
        Arguments:
        config - the AwsBillingDetailThreadConfiguration object
        csvreader - utils.CsvFile object
        curr_month - Y-M
        """

        rows = 0
        record_id = None
        current_record_id = None
        if config.record_id_column:
            record_id = config.get_last_record_id(curr_month)

        # loop over all lines in the csv file after the header and
        # transmit the cost metric for each one
        #pylint: disable=too-many-nested-blocks
        for row in csvreader:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                break

            if config.record_id_column:
                current_record_id = row[config.record_id_column]
                if record_id and current_record_id != record_id:
                    continue
                else:
                    record_id = None

            rows = rows + 1
            if config.maximum_number_of_rows:
                if rows >= config.maximum_number_of_rows:
                    self.logger.debug('Stopping after %d rows', rows)
                    break

            # point tags
            point_tags = {}
            for header, point_tag_key in config.dimensions.iteritems():
                if row[header]:
                    point_tags[point_tag_key] = row[header]

            # point tags beginning with user:
            if config.user_point_tags:
                for header in csvreader.header_key_to_index:
                    if header[0:5] == 'user:' and row[header]:
                        point_tags[header.replace(':', '_')] = row[header]

            # point tags from ec2 instance
            if config.instance_id_columns:
                found_instance = False
                for header in config.instance_id_columns:
                    instance_id = row[header]
                    if not instance_id and instance_id[0:2] == 'i-':
                        continue
                    for region in self.account.regions:
                        for sub_account in self.account.get_sub_accounts():
                            instances = sub_account.get_instances(region)
                            if instance_id in instances:
                                instance_tags = instances[instance_id]
                                for key, value in instance_tags.iteritems():
                                    point_tags[key] = value
                                found_instance = True
                                break
                        if found_instance:
                            break

                    if found_instance:
                        break

            # source names
            source, source_name = AwsCloudwatchMetricsCommand.get_source(
                config.source_names, point_tags)
            if source_name in point_tags:
                del point_tags[source_name]

            # timestamp
            tstamp = None
            for header, date_fmt in config.dates.iteritems():
                if row[header]:
                    tstamp = utils.unix_time_seconds(
                        datetime.datetime.strptime(row[header], date_fmt))

            if not tstamp:
                self.logger.warning('Unable to find valid date in %s',
                                    str(row))
                continue

            # calculate duration
            if config.duration and len(config.duration) == 2:
                start = config.duration[0].split('|')
                start_dt = datetime.datetime.strptime(row[start[0]],
                                                      start[1])
                start_tstamp = utils.unix_time_seconds(start_dt)

                end = config.duration[1].split('|')
                end_dt = datetime.datetime.strptime(row[end[0]], end[1])
                end_tstamp = utils.unix_time_seconds(end_dt)

                duration = end_tstamp - start_tstamp
            else:
                duration = 0

            # metric and value
            for header, metric_name in config.metrics.iteritems():
                if config.namespace:
                    metric = config.namespace + '.' + metric_name
                else:
                    metric = metric_name

                value = row[header]
                if not value:
                    value = 0.0

                # send the metric to the proxy
                self.proxy.transmit_metric(metric, value, long(tstamp),
                                           source, point_tags)
                if duration:
                    self.proxy.transmit_metric(metric + '.duration',
                                               duration, long(tstamp),
                                               source, point_tags)

            if config.sleep_after_rows and rows % config.sleep_after_rows == 0:
                self.logger.debug('Sleeping %0.2f', config.sleep_ms)
                time.sleep(config.sleep_ms)

        if current_record_id:
            config.set_last_record_id(curr_month, current_record_id)

class AwsCloudwatchMetricsCommand(AwsMetricsCommand):
    """
    Wavefront command for retrieving metrics from AWS cloudwatch.
    """

    def __init__(self, **kwargs):
        super(AwsCloudwatchMetricsCommand, self).__init__(**kwargs)
        self.metrics_config = None

    def _execute(self):
        """
        Execute this command
        """

        super(AwsCloudwatchMetricsCommand, self)._execute()
        self._process_cloudwatch()

    def _parse_args(self, arg):
        super(AwsCloudwatchMetricsCommand, self)._parse_args(arg)

    @staticmethod
    def get_source(source_names, point_tags, dimensions=None):
        """
        Determine the source from the point tags.
        Argument:
        source_names - the key names in priority order to use as source
        point_tags - all the point tags for this metric (dictionary)
        dimensions - the dimensions for this metric (list of objects)

        Returns:
        Tuple of (source value, key of the source of the source)
        """

        for name in source_names:
            if dimensions and isinstance(name, numbers.Number):
                if len(dimensions) < int(name):
                    return (dimensions[name], name)
                else:
                    continue

            if name[0:1] == '=':
                return (name[1:], None)

            if name in point_tags and point_tags[name]:
                return (point_tags[name], name)

            if dimensions:
                for dim in dimensions:
                    if dim['Name'] == name and dim['Value']:
                        return (dim['Value'], name)

        return (None, None)

    #pylint: disable=too-many-locals
    #pylint: disable=too-many-branches
    #pylint: disable=too-many-statements
    def _process_list_metrics_response(self, metrics, sub_account, region):
        """
        Loops over all metrics and call GetMetricStatistics() on each that are
        included by the configuration.

        Arguments:
        metrics - the array of metrics returned from ListMetrics() ('Metrics')
        sub_account - the AwsSubAccount object representing the top level
        """

        cloudwatch_config = self.config.get_cloudwatch_config(region)
        start = cloudwatch_config.start_time
        end = cloudwatch_config.end_time
        session = sub_account.get_session(region, False)
        cloudwatch = session.client('cloudwatch')
        account_id = sub_account.get_account_id()

        for metric in metrics:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                break

            top = (metric['Namespace']
                   .lower()
                   .replace('aws/', cloudwatch_config.namespace + '/')
                   .replace('/', '.'))
            metric_name = '{}.{}'.format(top, metric['MetricName'].lower())
            point_tags = {'Namespace': metric['Namespace'],
                          'Region': session.region_name,
                          'accountId': account_id}
            config = cloudwatch_config.get_metric_config(
                metric['Namespace'], metric['MetricName'])
            if config is None or len(config['stats']) == 0:
                self.logger.warning('No configuration found for %s/%s',
                                    metric['Namespace'], metric['MetricName'])
                continue

            dimensions = metric['Dimensions']
            for dim in dimensions:
                if ('dimensions_as_tags' in config and
                        dim['Name'] in config['dimensions_as_tags']):
                    point_tags[dim['Name']] = dim['Value']
                if sub_account.instances and dim['Name'] == 'InstanceId':
                    instance_id = dim['Value']
                    region_instances = sub_account.get_instances(region)
                    if instance_id in region_instances:
                        instance_tags = region_instances[instance_id]
                        for key, value in instance_tags.iteritems():
                            point_tags[key] = value
                    else:
                        self.logger.warning('%s not found in region %s',
                                            instance_id, region)

            source, _ = self.get_source(
                config['source_names'], point_tags, dimensions)
            if not source:
                self.logger.warning('Source is not found in %s', str(metric))
                continue

            curr_start = start
            if (end - curr_start).total_seconds() > 86400:
                curr_end = curr_start + datetime.timedelta(days=1)
            else:
                curr_end = end

            while (curr_end - curr_start).total_seconds() > 0:
                if utils.CANCEL_WORKERS_EVENT.is_set():
                    break
                stats = cloudwatch.get_metric_statistics(
                    Namespace=metric['Namespace'],
                    MetricName=metric['MetricName'],
                    Dimensions=dimensions,
                    StartTime=curr_start,
                    EndTime=curr_end,
                    Period=60,
                    Statistics=config['stats'])

                number_of_stats = len(config['stats'])
                for stat in stats['Datapoints']:
                    for statname in config['stats']:
                        if utils.CANCEL_WORKERS_EVENT.is_set():
                            return
                        short_name = STAT_SHORT_NAMES[statname]
                        if (number_of_stats == 1 and
                                cloudwatch_config.has_suffix_for_single_stat):
                            full_metric_name = metric_name
                        else:
                            full_metric_name = metric_name + '.' + short_name

                        # remove point tags that we don't need for WF
                        if 'Namespace' in point_tags:
                            del point_tags['Namespace']

                        # send the metric to the proxy
                        tstamp = int(utils.unix_time_seconds(stat['Timestamp']))
                        self.proxy.transmit_metric(full_metric_name,
                                                   stat[statname],
                                                   tstamp,
                                                   source,
                                                   point_tags)

                curr_start = curr_end
                if (end - curr_start).total_seconds() > 86400:
                    curr_end = curr_start + datetime.timedelta(days=1)
                else:
                    curr_end = end

    def _process_cloudwatch(self):

        # process each subaccount/region in parallel
        region_call_details = []
        for sub_account in self.account.get_sub_accounts():
            for region in self.account.regions:
                region_call_details.append((self._process_cloudwatch_region,
                                            (sub_account, region, )))

        self.logger.info('Processing %d region%s using %d threads',
                         len(self.account.regions),
                         's' if len(self.account.regions) > 1 else '',
                         len(self.account.regions))
        utils.parallel_process_and_wait(region_call_details,
                                        len(self.account.regions),
                                        self.logger)

    def _process_cloudwatch_region(self, sub_account, region):
        """
        Initialize and process a single region for a particular sub account.
        Response is paginated and each page is processed by its own thread
        Arguments:
        sub_account - the sub account
        region - the region name (us-west-1, etc)
        """

        cloudwatch_config = self.config.get_cloudwatch_config(region)
        cloudwatch_config.update_start_end_times()
        self.logger.info('Loading metrics %s - %s (Region: %s, Namespace: %s)',
                         str(cloudwatch_config.start_time),
                         str(cloudwatch_config.end_time),
                         region,
                         ', '.join(cloudwatch_config.namespaces))

        cloudwatch_config.load_metric_config()
        function_pointers = []
        session = sub_account.get_session(region, False)
        cloudwatch = session.client('cloudwatch')
        for namespace in cloudwatch_config.namespaces:
            paginator = cloudwatch.get_paginator('list_metrics')
            if namespace == 'AWS/EC2':
                # for ec2 only: query with a filter for each instance
                # if you call list_metrics() on its own it returns several
                # instances that are no longer running
                instances = sub_account.get_instances(region)
                for instance_id in instances.instances:
                    dimensions = [{
                        'Name': 'InstanceId',
                        'Value': instance_id
                    }]
                    response = paginator.paginate(Namespace=namespace,
                                                  Dimensions=dimensions)
                    for page in response:
                        if utils.CANCEL_WORKERS_EVENT.is_set():
                            break
                        function_pointers.append(
                            (self._process_list_metrics_response,
                             (page['Metrics'], sub_account, region)))

            else:
                response = paginator.paginate(Namespace=namespace)
                for page in response:
                    if utils.CANCEL_WORKERS_EVENT.is_set():
                        break
                    function_pointers.append(
                        (self._process_list_metrics_response,
                         (page['Metrics'], sub_account, region)))

        if utils.CANCEL_WORKERS_EVENT.is_set():
            return
        self.logger.info('Metrics retrieved for region %s.  '
                         'Processing %d items in %d threads ...',
                         region, len(function_pointers),
                         cloudwatch_config.workers)
        utils.parallel_process_and_wait(function_pointers,
                                        cloudwatch_config.workers,
                                        self.logger)
        if not utils.CANCEL_WORKERS_EVENT.is_set():
            cloudwatch_config.set_last_run_time(cloudwatch_config.end_time)
            self.logger.info('Last run time updated to %s for %s',
                             str(cloudwatch_config.last_run_time), region)
