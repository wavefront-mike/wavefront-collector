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
import csv
import datetime
import io
import json
import numbers
import os
import os.path
import re
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

# characters to replace in the operation when creating the metric name
SPECIAL_CHARS_REPLACE_MAP = {
    '/': '-',
    ':': '-'
}

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

        self.has_suffix_for_single_stat = self.getboolean(
            'options', 'single_stat_has_suffix', True)
        self.default_delay_minutes = int(self.get(
            'options', 'first_run_start_minutes', 5))
        self.metric_name_prefix = self.get('options', 'metric_name_prefix', '')
        self.top_level_name = self.get('options', 'top_level_name', 'aws')
        self.ec2_tag_keys = self.getlist('options', 'ec2_tag_keys', [])
        self.last_run_time = self.getdate('options', 'last_run_time', None)
        self.start_time = self.getdate('filter', 'start_time', None)
        self.end_time = self.getdate('filter', 'end_time', None)
        self._update_start_end_times()

        self.delay = int(self.get('options', 'delay', 300))
        self.number_of_threads = int(self.get('options', 'workers', 10))
        self.number_of_region_threads = int(
            self.get('options', 'region_workers', 1))

        self.cache_dir = self.get('options', 'cache_dir', '/tmp')
        self.metric_config_path = self.get(
            'options', 'metric_config_path', DEFAULT_METRIC_CONFIG_FILE)

        self.billing_s3_enabled = self.getboolean('billing', 'enabled', False)
        self.billing_s3_region = self.get('billing', 's3_region', None)
        self.billing_s3_bucket = self.get('billing', 's3_bucket', None)
        self.billing_s3_path = self.get('billing', 's3_path', None)

        self.aws_access_key_id = self.get('aws', 'access_key_id', None)
        self.aws_secret_access_key = self.get('aws', 'secret_access_key', None)
        self.regions = self.getlist('aws', 'regions', None)

        self.role_arn = self.get('assume_role', 'role_arn', None)
        self.role_session_name = self.get(
            'assume_role', 'role_session_name', None)
        self.role_external_id = self.get(
            'assume_role', 'role_external_id', None)

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
        self.config.set('options', 'last_run_time', run_time.isoformat())
        self.save()
        self.start_time = self.last_run_time
        self.end_time = utcnow

    def _update_start_end_times(self):
        """
        Updates start/end times after last_run_time set
        """

        utcnow = (datetime.datetime.utcnow()
                  .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        if self.start_time and self.end_time and self.last_run_time:
            if self.last_run_time > self.start_time:
                self.start_time = self.last_run_time
        elif self.last_run_time:
            self.start_time = self.last_run_time
            self.end_time = utcnow
        elif not self.start_time:
            delta = datetime.timedelta(minutes=self.default_delay_minutes)
            self.start_time = utcnow - delta
            self.end_time = utcnow

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

        if not self.metric_config_path:
            raise ValueError('options.metric_config_path is required')
        if not os.path.exists(self.metric_config_path):
            raise ValueError('ERROR: Configuration file (%s) does not exist' %
                             (self.metric_config_path))

#pylint: disable=too-few-public-methods
class AwsInstanceTags(object):
    """
    Queries and caches the tags of all instances in a region.  Results are
    cached in a configured directory.  Cached results are used if the
    date of the file is within the last day (using modified time).
    The configuration object stores the AWS tag keys to retrieve from each
    instance.  If this configuration is not set (blank or null), this
    class does nothing.
    """
    def __init__(self, region, config, **kwargs):
        """
        Initializes the class.
        Arguments:
        region - the region name
        config - the configuration object
        """

        super(AwsInstanceTags, self).__init__(**kwargs)
        self.region = region
        self.config = config
        fname = ('instance_tag_%s_cache_%s.json' %
                 (region.get_account_id(), region.name, ))
        self.cache_file_path = os.path.join(self.config.cache_dir, fname)
        self.instance_tags = None

    def _query_instance_tags(self):
        """
        Calls EC2.DescribeInstances() and retrieves all instances and their tags
        """

        self.instance_tags = {}
        for instance in self.region.get_instances():
            tags = {}

            # hard-coded instance attributes (data coming from instance object)
            if 'instanceType' in self.config.ec2_tag_keys:
                tags['instanceType'] = instance.instance_type
            if 'imageId' in self.config.ec2_tag_keys:
                tags['imageId'] = instance.instance_type
            if 'publicDnsName' in self.config.ec2_tag_keys:
                tags['publicDnsName'] = instance.public_dns_name
            if 'privateDnsName' in self.config.ec2_tag_keys:
                tags['privateDnsName'] = instance.private_dns_name
            if 'vpcId' in self.config.ec2_tag_keys:
                tags['vpcId'] = instance.vpc_id
            if 'architecture' in self.config.ec2_tag_keys:
                tags['architecture'] = instance.architecture

            # tags coming from the EC2 tags
            if instance.tags:
                for tag in instance.tags:
                    if (self.config.ec2_tag_keys[0] == '*' or
                            tag['Key'] in self.config.ec2_tag_keys):
                        tags[tag['Key']] = tag['Value']

            # store the tags in the dictionary
            self.instance_tags[instance.id] = tags

        # store the results on disk for next time
        with open(self.cache_file_path, 'w') as cachefd:
            json.dump(self.instance_tags, cachefd)

    def _load_instance_tags_from_cache(self):
        """
        Loads the tags from the cache file if it exists.
        Returns:
        True - when data loaded from cache; False - o/w
        """

        if os.path.exists(self.cache_file_path):
            now = datetime.datetime.utcnow()
            mtime = datetime.datetime.fromtimestamp(
                os.path.getmtime(self.cache_file_path))
            time_to_refresh = mtime + datetime.timedelta(days=1)
            if now > time_to_refresh:
                with open(self.cache_file_path, 'r') as contents:
                    self.instance_tags = json.load(contents)
                    return True

        return False

    def get(self):
        """
        Gets the instances and their tags.  Caches that data for at most one
        day (configurable?).
        """

        if self.instance_tags or not self.config.ec2_tag_keys:
            return self.instance_tags
        if not self._load_instance_tags_from_cache():
            self._query_instance_tags()
        return self.instance_tags

    def __contains__(self, item):
        return item in self.get()
    def __getitem__(self, item):
        return self.get()[item]

class AwsRegion(object):
    """
    Represents and wraps commands related to a single AWS region
    """

    def __init__(self, region, config, **kwargs):
        """
        Initializes the class.
        Arguments:
        region - the region name
        config - the configuration object
        """

        super(AwsRegion, self).__init__(**kwargs)
        if not region:
            raise ValueError('Region is required')

        self.name = region
        self.config = config
        self.instance_tags = AwsInstanceTags(self, config)
        self.session = None
        self.instances = None

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name

    def get_session(self):
        """
        Creates a new session object in this region lazily and returns that
        session.
        """
        if not self.session:
            if self.config.role_arn is not None:
                session = boto3.session.Session()
                client = session.client(
                    'sts',
                    region_name=self.name,
                    aws_access_key_id=self.config.aws_access_key_id,
                    aws_secret_access_key=self.config.aws_secret_access_key)
                role = client.assume_role(
                    RoleArn=self.config.role_arn,
                    ExternalId=self.config.role_external_id,
                    RoleSessionName=self.config.role_session_name)
                self.session = boto3.Session(
                    role['Credentials']['AccessKeyId'],
                    role['Credentials']['SecretAccessKey'],
                    role['Credentials']['SessionToken'],
                    region_name=self.name)

            else:
                self.session = boto3.Session(
                    region_name=self.name,
                    aws_access_key_id=self.config.aws_access_key_id,
                    aws_secret_access_key=self.config.aws_secret_access_key)

        return self.session

    def get_account_id(self):
        """
        Gets the account id
        """

        if self.config.role_arn is not None:
            return self.config.role_arn.split(':')[4]
        else:
            return (self.get_session().client('iam')
                    .get_user()['User']['Arn'].split(':')[4])

    def get_instances(self):
        """
        Gets all EC2 instances and caches result on this object
        NOTE: this is here for convenience and caching.  This probably belongs
        somewhere else (or removed all together).
        """
        if not self.instances:
            self.instances = self.get_session().resource('ec2').instances.all()
        return self.instances

class AwsMetricsCommand(command.Command):
    """
    Wavefront command for retrieving metrics from AWS cloudwatch.
    """

    def __init__(self, **kwargs):
        super(AwsMetricsCommand, self).__init__(**kwargs)
        self.metrics_config = None
        self.namespaces = None
        self.proxy = None
        self.config = None

    def _init_proxy(self):
        """
        Initializes the proxy writer
        """

        self.proxy = self.get_writer_from_config(self.config)

    def _init_logging(self):
        self.logger = logging.getLogger()

    @staticmethod
    def get_writer_from_config(config):
        """
        Creates a new metrics writer pointed to the proxy using the given
        config object and starts it

        Arguments:
        config - the configuration
        """
        proxy = WavefrontMetricsWriter(config.writer_host,
                                       config.writer_port,
                                       config.is_dry_run)
        proxy.start()
        return proxy

    def _load_metric_config(self):
        """
        Loads the metric configuration from the configuration file.
        """

        with open(self.config.metric_config_path, 'r') as conffd:
            config = json.load(conffd)

        if 'metrics' not in config:
            raise ValueError('ERROR: Configuration file (%s) is not valid' %
                             (self.config.metric_config_path))

        self.metrics_config = config['metrics']
        self.namespaces = set()
        for _, config in self.metrics_config.iteritems():
            if 'namespace' in config and config['namespace']:
                self.namespaces.add(config['namespace'])

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

    #pylint: disable=unsupported-membership-test
    #pylint: disable=unsubscriptable-object
    def get_metric_configuration(self, namespace, metric_name):
        """
        Given a namespace and metric, get the configuration.

        Arguments:
        namespace - the namespace
        metric_name - the metric's name

        Returns:
        the configuration for this namespace and metric
        """

        current_match = None
        metric = namespace.replace('/', '.').lower() + '.' + metric_name.lower()
        for name, config in self.metrics_config.iteritems():
            if re.match(name, metric, re.IGNORECASE):
                if current_match is None or \
                   ('priority' in current_match and \
                    current_match['priority'] < config['priority']):
                    current_match = config

        return current_match

    @staticmethod
    def _get_source(source_names, point_tags, dimensions=None):
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
    def _process_metrics(self, metrics, start, end, region):
        """
        Loops over all metrics and call GetMetricStatistics() on each that are
        included by the configuration.

        Arguments:
        metrics - the array of metrics returned from ListMetrics() ('Metrics')
        start - the start time
        end - the end time
        region - the AwsRegion object
        """

        session = region.get_session()
        cloudwatch = session.client('cloudwatch')
        account_id = region.get_account_id()

        for metric in metrics:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                break

            top = (metric['Namespace']
                   .lower()
                   .replace('aws/', self.config.top_level_name + '/')
                   .replace('/', '.'))
            metric_name = '{}.{}'.format(top, metric['MetricName'].lower())
            point_tags = {'Namespace': metric['Namespace'],
                          'Region': region.name,
                          'AccountId': account_id}
            config = self.get_metric_configuration(metric['Namespace'],
                                                   metric['MetricName'])
            if config is None or len(config['stats']) == 0:
                self.logger.warning('No configuration found for %s/%s',
                                    metric['Namespace'], metric['MetricName'])
                continue

            dimensions = metric['Dimensions']
            for dim in dimensions:
                if ('dimensions_as_tags' in config and
                        dim['Name'] in config['dimensions_as_tags']):
                    point_tags[dim['Name']] = dim['Value']
                if region.instance_tags and dim['Name'] == 'InstanceId':
                    instance_id = dim['Value']
                    if instance_id in region.instance_tags:
                        instance_tags = region.instance_tags[instance_id]
                        for key, value in instance_tags.iteritems():
                            point_tags[key] = value
                    else:
                        self.logger.warning('%s not found in region %s: %s',
                                            instance_id, region, str(metric))

            source, _ = self._get_source(
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
                                self.config.has_suffix_for_single_stat):
                            full_metric_name = metric_name
                        else:
                            full_metric_name = metric_name + '.' + short_name

                        # remove point tags that we don't need for WF
                        if 'Namespace' in point_tags:
                            del point_tags['Namespace']

                        # send the metric to the proxy
                        tstamp = int(utils.unix_time_seconds(stat['Timestamp']))
                        self.proxy.transmit_metric(
                            self.config.metric_name_prefix + full_metric_name,
                            stat[statname],
                            tstamp,
                            source,
                            point_tags)

                curr_start = curr_end
                self.config.set_last_run_time(curr_end)
                if (end - curr_start).total_seconds() > 86400:
                    curr_end = curr_start + datetime.timedelta(days=1)
                else:
                    curr_end = end

    def process_billing_details(self):
        """
        Processes the latest billing details CSV file.  A few helpful sites:
        http://www.dowdandassociates.com/products/cloud-billing/documentation/1.0/schema/
        http://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/detailed-billing-reports.html#reportstagsresources
        """

        if not self.config.billing_s3_enabled:
            return
        if utils.CANCEL_WORKERS_EVENT.is_set():
            return

        s3region = AwsRegion(self.config.billing_s3_region, self.config)
        s3cli = s3region.get_session().client('s3')
        prefix = (
            '%s-aws-billing-detailed-line-items-with-resources-and-tags-%s' %
            (s3region.get_account_id(),
             self.config.start_time.strftime('%Y-%m')))
        response = s3cli.list_objects(Bucket=self.config.billing_s3_bucket,
                                      Prefix=prefix)
        if (not response or 'Contents' not in response or
                not response['Contents']):
            self.logger.warning('Billing details file [%s] not found\n%s',
                                prefix, str(response))
            return

        key = response['Contents'][0]['Key']
        response = s3cli.get_object(Bucket=self.config.billing_s3_bucket,
                                    Key=key)
        if not response or not response['Body']:
            self.logger.warning('Billing details file body not found')

        contents = io.BytesIO(response['Body'].read())
        self.logger.info('Reading billing information from |%s|', key)
        with zipfile.ZipFile(contents, 'r') as zipfd:
            csv_contents = io.BytesIO(zipfd.read(prefix + '.csv'))
            csvreader = csv.reader(csv_contents)
            # InvoiceID,PayerAccountId,LinkedAccountId,RecordType,RecordId,
            # ProductName,RateId,SubscriptionId,PricingPlanId,UsageType,
            # Operation,AvailabilityZone,ReservedInstance,ItemDescription,
            # UsageStartDate,UsageEndDate,UsageQuantity,BlendedRate,BlendedCost,
            # UnBlendedRate,UnBlendedCost,ResourceId
            header_row = csvreader.next()
            header_key_to_index = {}
            index = 0
            for name in header_row:
                header_key_to_index[name] = index
                index = index + 1

            # loop over all lines in the csv file after the header and
            # transmit the cost metric for each one
            for row in csvreader:
                if utils.CANCEL_WORKERS_EVENT.is_set():
                    break
                point_tags = {
                    'accountid': row[header_key_to_index['PayerAccountId']]
                }
                azone = row[header_key_to_index['AvailabilityZone']]
                resource_id = row[header_key_to_index['ResourceId']]
                if azone:
                    point_tags['az'] = azone
                    point_tags['region'] = azone[0:-1]
                if resource_id:
                    point_tags['resourceid'] = resource_id

                source, source_name = self._get_source(
                    ['resourceid', '=AWS'], point_tags)
                if source_name == 'resourceid':
                    del point_tags['resourceid']
                product = utils.get_aws_product_short_name(
                    row[header_key_to_index['ProductName']])
                metric = (self.config.top_level_name + '.' + product +
                          '.cost.' + utils.sanitize_name(
                              row[header_key_to_index['Operation']],
                              SPECIAL_CHARS_REPLACE_MAP))

                edate = row[header_key_to_index['UsageEndDate']]
                # 2016-06-01 01:00:00
                tstamp = utils.unix_time_seconds(
                    datetime.datetime.strptime(edate, '%Y-%m-%d %H:%M:%S'))

                value = row[header_key_to_index['BlendedCost']]
                if not value:
                    value = 0.0

                # send the metric to the proxy
                self.proxy.transmit_metric(
                    self.config.metric_name_prefix + metric,
                    value,
                    long(tstamp),
                    source,
                    point_tags)

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
        self._load_metric_config()
        self.process_billing_details()

        # process each region in parallel
        region_call_details = []
        for region in self.config.regions:
            region_call_details.append((self._process_region, (region, )))

        self.logger.info('Processing %d region%s using %d threads',
                         len(self.config.regions),
                         's' if len(self.config.regions) > 1 else '',
                         self.config.number_of_region_threads)
        utils.parallel_process_and_wait(region_call_details,
                                        self.config.number_of_region_threads,
                                        self.logger)

    def _process_region(self, region_name):
        """
        Initialize and process a single region
        Arguments:
        region_name - the region name (us-west-1, etc)
        """

        region = AwsRegion(region_name, self.config)
        self.logger.info('Loading metrics %s - %s (Region: %s)',
                         str(self.config.start_time),
                         str(self.config.end_time),
                         region_name)

        function_pointers = []
        cloudwatch = region.get_session().client('cloudwatch')
        for namespace in self.namespaces:
            paginator = cloudwatch.get_paginator('list_metrics')
            if namespace == 'AWS/EC2':
                # for ec2 only: query with a filter for each instance
                # if you call list_metrics() on its own it returns several
                # instances that are no longer running
                for instance in region.get_instances():
                    dimensions = [{
                        'Name': 'InstanceId',
                        'Value': instance.id
                    }]
                    response = paginator.paginate(Namespace=namespace,
                                                  Dimensions=dimensions)
                    for page in response:
                        if utils.CANCEL_WORKERS_EVENT.is_set():
                            break
                        function_pointers.append((self.process_metrics_thread,
                                                  (page['Metrics'], region)))

            else:
                response = paginator.paginate(Namespace=namespace)
                for page in response:
                    if utils.CANCEL_WORKERS_EVENT.is_set():
                        break
                    function_pointers.append((self.process_metrics_thread,
                                              (page['Metrics'], region)))

        if utils.CANCEL_WORKERS_EVENT.is_set():
            return
        self.logger.info('Metrics retrieved for region %s.  '
                         'Processing %d items in %d threads ...',
                         region, len(function_pointers),
                         self.config.number_of_threads)
        utils.parallel_process_and_wait(function_pointers,
                                        self.config.number_of_threads,
                                        self.logger)

    def process_metrics_thread(self, metrics, region):
        """
        worker thread function for process_region parallel processing
        Arguments:
        metrics - the metrics to process
        region - the region object
        """

        self._process_metrics(metrics,
                              self.config.start_time,
                              self.config.end_time,
                              region)
