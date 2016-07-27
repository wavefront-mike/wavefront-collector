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
import os
import os.path
import re

import logging.config

import dateutil

from wavefront.aws_common import AwsBaseMetricsCommand, AwsBaseMetricsConfiguration
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

#pylint: disable=too-many-instance-attributes
class AwsMetricsConfiguration(AwsBaseMetricsConfiguration):
    """
    Configuration file for this command
    """

    def __init__(self, config_file_path):
        super(AwsMetricsConfiguration, self).__init__(
            config_file_path=config_file_path)

        self.cloudwatch = {}
        for region in self.regions:
            self.cloudwatch[region] = AwsCloudwatchConfiguration(self, region)

    def get_region_config(self, region):
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

class AwsCloudwatchMetricsCommand(AwsBaseMetricsCommand):
    """
    Wavefront command for retrieving metrics from AWS cloudwatch.
    """

    def __init__(self, **kwargs):
        super(AwsCloudwatchMetricsCommand, self).__init__(**kwargs)
        self.metrics_config = None

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

        super(AwsCloudwatchMetricsCommand, self)._execute()
        self._process_cloudwatch()

    #pylint: disable=too-many-locals
    #pylint: disable=too-many-branches
    #pylint: disable=too-many-statements
    def _process_list_metrics_response(self, metrics, sub_account, region):
        """
        This function is called by _process_cloudwatch_region() after calling
        list_metrics() API.

        Loops over all metrics and call GetMetricStatistics() on each that are
        included by the configuration.

        Arguments:
        metrics - the array of metrics returned from ListMetrics() ('Metrics')
        sub_account - the AwsSubAccount object representing the top level
        """

        cloudwatch_config = self.config.get_region_config(region)
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

            source, _ = AwsBaseMetricsCommand.get_source(
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

        cloudwatch_config = self.config.get_region_config(region)
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
