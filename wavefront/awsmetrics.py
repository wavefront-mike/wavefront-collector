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
import json
import numbers
import os
import os.path
import re

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
#        The first match is returned as the source name.  if source_names is
#        not present in the configuration, default_source_names array is used.
#
# The key to the dictionary is a regular expression that should match a:
#     <namespace>.<metric_name> (lower case with /=>.)
#
DEFAULT_METRIC_CONFIG_FILE = './aws-metrics.json.conf'

# default configuration
DEFAULT_CONFIG_FILE = '/opt/wavefront/etc/aws-metrics.conf'

# List of potential key names for the source/host value (can be overriden
# in the above namespace configuration)
# A numeric value in this means that that index in the Dimensions is chosen
DEFAULT_SOURCE_NAMES = ['Name', 'InstanceId', 'Service', 'AvailabilityZone', 0, 'Namespace', '=AWS']

# Mapping for statistic name to its "short" name.  The short name is used
# in the metric name sent to Wavefront
STAT_SHORT_NAMES = {
    'Average': 'avg',
    'Minimum': 'min',
    'Maximum': 'max',
    'Sum': 'sum',
    'SampleCount': 'count'
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
        self.ec2_tag_keys = self.getlist('options', 'ec2_tag_keys', [])
        self.last_run_time = self.getdate('options', 'last_run_time', None)
        self.start_time = self.getdate('filter', 'start_time', None)
        self.end_time = self.getdate('filter', 'end_time', None)

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

        self.delay = int(self.get('options', 'delay', 300))
        self.cache_dir = self.get('options', 'cache_dir', '/tmp')
        self.metric_config_path = self.get(
            'options', 'metric_config_path', DEFAULT_METRIC_CONFIG_FILE)

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

        if not run_time:
            run_time = (datetime.datetime.utcnow()
                        .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        self.config.set('options', 'last_run_time', run_time.isoformat())
        self.save()

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

class AwsMetricsCommand(command.Command):
    """
    Wavefront command for retrieving metrics from AWS cloudwatch.
    """

    def __init__(self, **kwargs):
        super(AwsMetricsCommand, self).__init__(**kwargs)
        self.aws_cloudwatch_client = None
        self.aws_ec2_client = None
        self.aws_ec2_resource = None
        self.metrics_config = None
        self.instance_tags = {}
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
    def _get_source(config, point_tags, dimensions):
        """
        Determine the source from the point tags.
        Argument:
        config - the configuration returned from get_metric_configuration()
        point_tags - all the point tags for this metric (dictionary)
        dimensions - the dimensions for this metric (dictionary)

        Returns:
        Tuple of (source value, key of the source of the source)
        """

        if 'source_names' in config:
            source_names = config['source_names']
        else:
            source_names = DEFAULT_SOURCE_NAMES

        for name in source_names:
            if isinstance(name, numbers.Number):
                if len(dimensions) < int(name):
                    return (dimensions[name], name)
                else:
                    continue

            if name[0:1] == '=':
                return (name[1:], None)

            if name in point_tags:
                return (point_tags[name], name)

        return (None, None)

    #pylint: disable=too-many-locals
    #pylint: disable=too-many-branches
    def _process_metrics(self, metrics, start, end, region):
        """
        Loops over all metrics and call GetMetricStatistics() on each that are
        included by the configuration.

        Arguments:
        metrics - the array of metrics returned from ListMetrics() ('Metrics')
        start - the start time
        end - the end time
        region - the AWS region
        """

        for metric in metrics:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                break
            metric_name = '{}.{}'.format(
                metric['Namespace'].lower().replace('/', '.'),
                metric['MetricName'].lower())
            point_tags = {'Namespace': metric['Namespace'],
                          'Region': region}
            for dim in metric['Dimensions']:
                point_tags[dim['Name']] = dim['Value']
                if self.instance_tags and dim['Name'] == 'InstanceId':
                    instance_id = dim['Value']
                    if instance_id in self.instance_tags:
                        instance_tags = self.instance_tags[instance_id]
                        for key, value in instance_tags.iteritems():
                            point_tags[key] = value

            config = self.get_metric_configuration(metric['Namespace'],
                                                   metric['MetricName'])
            if config is None or len(config['stats']) == 0:
                continue

            source, source_key = self._get_source(
                config, point_tags, metric['Dimensions'])
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
                stats = self.aws_cloudwatch_client.get_metric_statistics(
                    Namespace=metric['Namespace'],
                    MetricName=metric['MetricName'],
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
                            tstamp * 1000,
                            source,
                            point_tags)

                curr_start = curr_end
                if (end - curr_start).total_seconds() > 86400:
                    curr_end = curr_start + datetime.timedelta(days=1)
                else:
                    curr_end = end

    def _reload_instance_data(self, region):
        """
        Calls EC2.DescribeInstances() and retrieves all instances and their tags
        Arguments:
        region - the region name
        Side Effects:
        self.instance_tags updated
        """

        self.instance_tags = {}

        if not self.config.ec2_tag_keys:
            return

        self.logger.info('Retrieving instances ...')
        for instance in self.aws_ec2_resource.instances.all():
            tags = {}
            if instance.tags:
                for tag in instance.tags:
                    if (self.config.ec2_tag_keys[0] == '*' or
                            tag['Key'] in self.config.ec2_tag_keys):
                        tags[tag['Key']] = tag['Value']
            self.instance_tags[instance.id] = tags

        # cache the results
        fname = ('instance_tag_cache_%s.json' % (region, ))
        path = os.path.join(self.config.cache_dir, fname)
        with open(path, 'w') as cachefd:
            json.dump(self.instance_tags, cachefd)

    def _populate_instance_tags(self, region):
        """
        Gets the instances and their tags.  Caches that data for at most one
        day (configurable?).
        Arguments:
        region - the region name
        """

        if not self.config.ec2_tag_keys:
            return

        fname = ('instance_tag_cache_%s.json' % (region, ))
        path = os.path.join(self.config.cache_dir, fname)
        if os.path.exists(path):
            now = datetime.datetime.utcnow()
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            time_to_refresh = mtime + datetime.timedelta(days=1)
            if now < time_to_refresh:
                self._reload_instance_data(region)
            else:
                self.logger.info('Loading instance data from cache ...')
                with open(path, 'r') as contents:
                    self.instance_tags = json.load(contents)
        else:
            self._reload_instance_data(region)

    #pylint: disable=no-self-use
    def get_help_text(self):
        """
        Returns help text for --help of this wavefront command
        """
        return "Pull metrics from AWS CloudWatch and push them into Wavefront"

    def _initialize_aws_client(self, region):
        """
        Sets up the AWS clients for EC2 and CloudWatch using the role if
        required.
        Arguments:
        region - the region to use when connecting with AWS
        """

        if self.config.role_arn is not None:
            client = boto3.client(
                'sts', region_name=region,
                aws_access_key_id=self.config.aws_access_key_id,
                aws_secret_access_key=self.config.aws_secret_access_key)
            role = client.assume_role(
                RoleArn=self.config.role_arn,
                ExternalId=self.config.role_external_id,
                RoleSessionName=self.config.role_session_name)
            session = boto3.Session(role['Credentials']['AccessKeyId'],
                                    role['Credentials']['SecretAccessKey'],
                                    role['Credentials']['SessionToken'],
                                    region_name=region)
            self.aws_cloudwatch_client = session.client('cloudwatch')
            self.aws_ec2_client = session.client('ec2')
            self.aws_ec2_resource = session.resource('ec2')

        else:
            self.aws_cloudwatch_client = boto3.client(
                'cloudwatch', region_name=region,
                aws_access_key_id=self.config.aws_access_key_id,
                aws_secret_access_key=self.config.aws_secret_access_key)
            self.aws_ec2_client = boto3.client(
                'ec2', region_name=region,
                aws_access_key_id=self.config.aws_access_key_id,
                aws_secret_access_key=self.config.aws_secret_access_key)
            self.aws_ec2_resource = session.resource(
                'ec2', region_name=region,
                aws_access_key_id=self.config.aws_access_key_id,
                aws_secret_access_key=self.config.aws_secret_access_key)

    def _execute(self):
        """
        Execute this command
        """

        self._init_proxy()
        self._load_metric_config()

        # ListMetrics() API for each region
        for region in self.config.regions:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                return

            self._initialize_aws_client(region)
            self._populate_instance_tags(region)
            self.logger.info('Loading metrics for %s - %s (Region: %s)',
                             str(self.config.start_time),
                             str(self.config.end_time),
                             region)
            response = self.aws_cloudwatch_client.list_metrics()
            metrics_available = 'Metrics' in response
            while metrics_available and not utils.CANCEL_WORKERS_EVENT.is_set():
                self._process_metrics(response['Metrics'],
                                      self.config.start_time,
                                      self.config.end_time,
                                      region)
                if 'NextToken' in response:
                    response = self.aws_cloudwatch_client.list_metrics(
                        NextToken=response['NextToken'])
                    metrics_available = 'Metrics' in response
                else:
                    metrics_available = False

        self.config.set_last_run_time(self.config.end_time)
