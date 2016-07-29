#!/usr/bin/env python
"""
This script pulls metrics from App Dynamics.  See the README for
more details on configuration.
This script relies on the AppDynamicsREST package available from pip.
(https://github.com/tradel/AppDynamicsREST)
"""

import ConfigParser
import datetime
import numbers
import re
import sys
import time

import logging.config
import dateutil.parser

from appd.request import AppDynamicsClient
from wavefront import command
from wavefront.metrics_writer import WavefrontMetricsWriter
from wavefront.utils import Configuration
from wavefront import utils

# default location for the configuration file.
DEFAULT_CONFIG_FILE_PATH = '/opt/wavefront/etc/wavefront-collector-appd.conf'

#pylint: disable=too-many-instance-attributes
class AppDPluginConfiguration(Configuration):
    """
    Stores the configuration for this plugin
    """

    #pylint: disable=too-many-statements
    def __init__(self, config_file_path):
        super(AppDPluginConfiguration, self).__init__(
            config_file_path=config_file_path)

        self.api_url = self.get('api', 'controller_url', None)
        self.api_username = self.get('api', 'username', None)
        self.api_password = self.get('api', 'password', None)
        self.api_account = self.get('api', 'account', None)
        self.api_debug = self.getboolean('api', 'debug', False)

        self.fields = self.getlist('filter', 'names', [])
        self.fields_regex = self.getlist('filter', 'regex', [])
        self.fields_regex_compiled = []
        for regex in self.fields_regex:
            self.fields_regex_compiled.append(re.compile(regex))
        self.fields_blacklist_regex = self.getlist(
            'filter', 'blacklist_regex', [])
        self.fields_blacklist_regex_compiled = []
        for regex in self.fields_blacklist_regex:
            self.fields_blacklist_regex_compiled.append(re.compile(regex))
        self.additional_fields = self.getlist('filter', 'additional_fields', [])
        self.application_ids = self.getlist('filter', 'application_ids', [])
        self.start_time = self.get('filter', 'start_time', None)
        self.end_time = self.get('filter', 'end_time', None)

        self.last_run_time = self.get('options', 'last_run_time', None)
        if self.start_time and self.end_time and self.last_run_time:
            if self.last_run_time > self.start_time:
                self.start_time = self.last_run_time
        elif self.last_run_time:
            self.start_time = self.last_run_time

        self.namespace = self.get('options', 'namespace', 'appd')
        self.min_delay = int(self.get('options', 'min_delay', 60))
        self.skip_null_values = self.getboolean(
            'options', 'skip_null_values', False)
        self.default_null_value = self.get('options', 'default_null_value', 0)

        self.writer_host = self.get('writer', 'host', '127.0.0.1')
        self.writer_port = int(self.get('writer', 'port', '2878'))
        self.is_dry_run = self.getboolean('writer', 'dry_run', True)

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

    def get_value_to_send(self, name, value):
        """
        Gets the value to send for the given value.  This allows us to translate
        the value from "NaN" to "0", for example.
        This function returns None when it should not be sent.
        Arguments:
        name - the name of the metric
        value - the value to check

        Return:
        The value to send or None to not send
        """

        if (not value or
                str(value).lower() == 'nan' or
                not isinstance(value, numbers.Number)):
            value = self.default_null_value

        return value

    def validate(self):
        """
        Checks that all required configuration items are set
        Throws:
        ValueError when a configuration item is missing a value
        """

        if not self.api_username:
            raise ValueError('api.username configuration is required')
        if not self.api_password:
            raise ValueError('api.password configuration is required')
        if not self.api_account:
            raise ValueError('api.account configuration is required')
        if not self.api_url:
            raise ValueError('api.controller_url configuration is required')

class AppDMetricRetrieverCommand(command.Command):
    """
    Command object for retrieving AppD metrics via the REST API.
    """

    def __init__(self, **kwargs):
        super(AppDMetricRetrieverCommand, self).__init__(**kwargs)
        self.description = 'AppDynamics Metric Retriever'
        self.appd_client = None
        self.config = None
        self.proxy = None

    #pylint: disable=too-many-arguments
    #pylint: disable=bare-except
    def send_metric(self, writer, name, value, host, timestamp, tags=None,
                    value_translator=None, logger=None):
        """
        Sends the metric to writer.

        Arguments:
        name - the metric name
        value - the numeric value
        host - the source/host
        timestamp - the timestamp (epoch seconds) or datetime object
        tags - dictionary of tags
        value_translator - function pointer to function that will translate
            value from current form to something else
        """

        if not isinstance(timestamp, numbers.Number):
            parsed_date = datetime.datetime.strptime(timestamp,
                                                     '%Y-%m-%dT%H:%M:%S+00:00')
            parsed_date = parsed_date.replace(tzinfo=dateutil.tz.tzutc())
            timestamp = utils.unix_time_seconds(parsed_date)

        if value_translator:
            value = value_translator(name, value)
            if value is None:
                return

        attempts = 0
        while attempts < 5 and not utils.CANCEL_WORKERS_EVENT.is_set():
            try:
                writer.transmit_metric(self.config.namespace + '.' +
                                       utils.sanitize_name(name),
                                       value, int(timestamp), host, tags)
                break
            except:
                attempts = attempts + 1
                logger.warning('Failed to transmit metric %s: %s',
                               name, str(sys.exc_info()))
                if not utils.CANCEL_WORKERS_EVENT.is_set():
                    time.sleep(1)

    #pylint: disable=no-self-use
    def get_help_text(self):
        """
        Help text for this command.
        """

        return "Pull metrics from AppDynamics"

    def _initialize(self, arg):
        """
        Parses the arguments passed into this command.

        Arguments:
        arg - the argparse parser object returned from argparser
        """

        self.config = AppDPluginConfiguration(arg.config_file_path)
        self.config.validate()
        try:
            logging.config.fileConfig(arg.config_file_path)
        except ConfigParser.NoSectionError:
            pass
        self.logger = logging.getLogger()

    #pylint: disable=too-many-branches
    def _execute(self):
        """
        Execute this command
        """

        # connect to the wf proxy
        self.proxy = WavefrontMetricsWriter(self.config.writer_host,
                                            self.config.writer_port,
                                            self.config.is_dry_run)
        self.proxy.start()

        # connect to appd
        self.appd_client = AppDynamicsClient(self.config.api_url,
                                             self.config.api_username,
                                             self.config.api_password,
                                             self.config.api_account,
                                             self.config.api_debug)

        # construct start time for when to get metrics starting from
        if self.config.start_time:
            start = (dateutil.parser.parse(self.config.start_time)
                     .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        else:
            start = ((datetime.datetime.utcnow() -
                      datetime.timedelta(seconds=60.0))
                     .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        if self.config.end_time:
            end = (dateutil.parser.parse(self.config.end_time)
                   .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        else:
            end = None

        if start is not None:
            if end is None:
                end = (datetime.datetime.utcnow()
                       .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))

            if (end - start).total_seconds() < self.config.min_delay:
                self.logger.info('Not running since %s - %s < 60',
                                 str(end), str(start))
                return

        start = start.replace(microsecond=0, tzinfo=dateutil.tz.tzutc())
        self.logger.info('Running %s - %s', str(start), str(end))

        for app in self.appd_client.get_applications():
            if str(app.id) not in self.config.application_ids:
                print 'skipping %s (%s)' % (app.name, str(app.id))
                continue
            if utils.CANCEL_WORKERS_EVENT.is_set():
                break

            # get a list of metrics available
            # TODO: cache this like New Relic plugin
            metric_tree = self.appd_client.get_metric_tree(app.id, None, True)

            # if the time is more than 10 minutes, AppD will make sample size
            # larger than a minute.  so, we'll grab the data in chunks
            # (10m at a time)
            curr_start = start
            if not end:
                end = (datetime.datetime.utcnow()
                       .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
            curr_end = end
            curr_diff = curr_end - curr_start
            while (curr_diff.total_seconds() > 0 and
                   not utils.CANCEL_WORKERS_EVENT.is_set()):
                if (curr_diff.total_seconds() > 600 or
                        curr_diff.total_seconds() < 60):
                    curr_end = curr_start + datetime.timedelta(minutes=10)

                for node in metric_tree:
                    if utils.CANCEL_WORKERS_EVENT.is_set():
                        break
                    print str(node)
                    metrics = self.appd_client.get_metrics(
                        node.path, app.id, 'BETWEEN_TIMES', None, curr_start,
                        curr_end, False)

                    for metric in metrics:
                        print str(metric)

                # save "last run time" and update curr_* variables
                self.config.set_last_run_time(curr_end)
                curr_start = curr_end
                curr_end = end
                curr_diff = curr_end - curr_start
                if (curr_diff.total_seconds() > 600 and
                        not utils.CANCEL_WORKERS_EVENT.is_set()):
                    time.sleep(30)
