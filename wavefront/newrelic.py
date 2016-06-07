#!/usr/bin/env python
"""
This script is intended to be run either manually from the command line or
via cron.  It pulls metrics from New Relic.  See the README for
more details on configuration.
"""

import ConfigParser
import datetime
import hashlib
import json
import numbers
import os
import os.path
import re
import time

import logging.config
import dateutil.parser

from wavefront.utils import Configuration, parallel_process_and_wait
from wavefront import utils
from wavefront.newrelic_common import NewRelicCommand

# default number of metric names to include with each GetMetricData
# API call
DEFAULT_MAX_METRIC_NAME_COUNT = 25

# default location for the configuration file.
DEFAULT_CONFIG_FILE_PATH = '/opt/wavefront/etc/newrelic.conf'

#pylint: disable=too-many-instance-attributes
class NewRelicPluginConfiguration(Configuration):
    """
    Stores the configuration for this plugin
    """

    #pylint: disable=too-many-statements
    def __init__(self, config_file_path):
        super(NewRelicPluginConfiguration, self).__init__(
            config_file_path=config_file_path)

        self.api_key = self.get('api', 'key', '')
        self.api_endpoint = self.get(
            'api', 'endpoint', 'https://api.newrelic.com/v2')
        self.api_key_header_name = self.get(
            'api', 'key_header_name', 'X-Api-Key')
        self.api_log_path = self.get('api', 'log_path', None)

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
        self.last_run_time = self.get('options', 'last_run_time', None)
        self.end_time = self.get('filter', 'end_time', None)
        if self.start_time and self.end_time and self.last_run_time:
            if self.last_run_time > self.start_time:
                self.start_time = self.last_run_time
        elif self.last_run_time:
            self.start_time = self.last_run_time

        self.include_application_summary = self.getboolean(
            'options', 'include_application_summary', True)
        self.include_host_app_summary = self.getboolean(
            'options', 'include_host_application_summary', True)
        self.include_server_summary = self.getboolean(
            'options', 'include_server_summary', True)
        self.include_servers = self.getboolean(
            'options', 'include_server_details', False)
        self.include_hosts = self.getboolean('options', 'include_hosts', True)
        self.min_delay = int(self.get('options', 'min_delay', 60))
        self.wf_api_key = self.get('wavefront_api', 'key', '')
        self.wf_api_endpoint = self.get(
            'wavefront_api', 'endpoint', 'https://metrics.wavefront.com/')
        self.skip_null_values = self.getboolean(
            'options', 'skip_null_values', False)
        self.default_null_value = self.get('options', 'default_null_value', 0)
        self.max_metric_names = int(self.get(
            'options', 'max_metric_names', DEFAULT_MAX_METRIC_NAME_COUNT))
        self.delay = int(self.get('options', 'delay', 0))
        self.writer_host = self.get('writer', 'host', '127.0.0.1')
        self.writer_port = int(self.get('writer', 'port', '2878'))
        self.is_dry_run = self.getboolean('writer', 'dry_run', True)

        self.query_api_key = self.get('query_api', 'key', '')
        self.query_api_endpoint = self.get(
            'query_api', 'endpoint', 'https://insights-api.newrelic.com/v1')
        self.query_api_key_header_name = self.get(
            'query_api', 'key_header_name', 'X-Query-Key')

        self.queries = {}
        for section in self.config.sections():
            if section[0:5].lower() == 'query':
                if self.getboolean(section, 'enabled', True):
                    name = self.get(section, 'name', 'query')
                    query = self.get(section, 'query', '')
                    self.queries[name] = query
        self.workers = int(self.get('options', 'workers', 30))
        self.cache_directory = '/tmp/wfnrcache'
        if not os.path.exists(self.cache_directory):
            os.makedirs(self.cache_directory)

        self.metric_last_sent = {}
        self.send_zero_every = int(self.get('options', 'send_zero_every', 0))

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

        if self.send_zero_every:
            current = (datetime.datetime.utcnow()
                       .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
            if value == 0 and name in self.metric_last_sent:
                last_sent = self.metric_last_sent[name]
                if (current - last_sent).total_seconds() < self.send_zero_every:
                    value = None
            self.metric_last_sent[name] = current

        return value

    def validate(self):
        """
        Checks that all required configuration items are set
        Throws:
        ValueError when a configuration item is missing a value
        """

        if not self.api_key:
            raise ValueError('api.key configuration is required')
        if not self.api_endpoint:
            raise ValueError('api.endpoint configuration is required')

class NewRelicMetricRetrieverCommand(NewRelicCommand):
    """
    Command object for retrieving New Relic metrics via the REST API.
    """

    def __init__(self, **kwargs):
        super(NewRelicMetricRetrieverCommand, self).__init__(**kwargs)
        self.description = 'New Relic Metric Retriever'

        # cache of metric names for given host-app
        # Key is application_id-host_id
        # Value is a dictionary:
        #   last_refresh - a datetime object in UTC of the last time value
        #                  is refreshed
        #   value - the list of metric names (list of strings)
        self.metric_name_cache = {}

    #pylint: disable=no-self-use
    def get_help_text(self):
        """
        Help text for this command.
        """

        return "Pull metrics from New Relic"

    #pylint: disable=no-self-use
    def add_arguments(self, parser):
        """
        Adds arguments for this command to the parser.

        Arguments:
        parser - the argparse parser created using .add_parser()
        """

        parser.add_argument('--config',
                            dest='config_file_path',
                            default=DEFAULT_CONFIG_FILE_PATH,
                            help='Path to configuration file')

    def _parse_args(self, arg):
        """
        Parses the arguments passed into this command.

        Arguments:
        arg - the argparse parser object returned from parser.parse_args()
        """

        self.config = NewRelicPluginConfiguration(arg.config_file_path)
        self.config.validate()
        try:
            logging.config.fileConfig(arg.config_file_path)
        except ConfigParser.NoSectionError:
            pass

    def get_metric_names_for_path(self, path, names_filter):
        """
        Gets the metric names for the given URL path.

        Arguments:
        path - the URL path
        names_filter - list of names to filter (additional calls)

        Returns:
        A list of string metric names
        """

        self.logger.debug('Getting metric names for %s', path)

        if utils.CANCEL_WORKERS_EVENT.is_set():
            return []

        # get a hash value instead of using path so we can store on disk
        hashval = hashlib.md5(path).hexdigest()
        filepath = self.config.cache_directory + '/' + hashval

        # cache this list so we only call once per day
        now = datetime.datetime.utcnow()
        if hashval not in self.metric_name_cache:
            if os.path.exists(filepath):
                with open(filepath, 'r') as contents:
                    names = json.load(contents)
                    self.metric_name_cache[hashval] = {
                        'value': names,
                        'last_refresh': datetime.datetime.fromtimestamp(
                            os.path.getmtime(filepath))
                    }

        if hashval in self.metric_name_cache:
            last_refresh = self.metric_name_cache[hashval]['last_refresh']
            time_to_refresh = last_refresh + datetime.timedelta(days=1)
            self.logger.debug('Checking %s; Last Refresh: %s; '
                              'Time to Refresh: %s',
                              path, str(last_refresh), str(time_to_refresh))
            if now < time_to_refresh:
                return self.metric_name_cache[hashval]['value']

            else:
                self.logger.debug('Refreshing metric names for %s; '
                                  'Last Refresh: %s; Time to Refresh: %s',
                                  path, str(last_refresh),
                                  str(time_to_refresh))

        names = []
        response = self.call_paginated_api(
            path + '/metrics.json', None, None, None)
        for page in response:
            metrics = page['metrics']
            for metric in metrics:
                names.append(metric['name'])

        for name in names_filter:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                return []
            response = self.call_paginated_api(
                path + '/metrics.json', {"name": name}, None, None)
            for page in response:
                metrics = page['metrics']
                for metric in metrics:
                    names.append(metric['name'])

        self.metric_name_cache[hashval] = {
            'last_refresh': now,
            'value': names
        }
        with open(filepath, 'w') as contents:
            json.dump(names, contents)

        return names

    def _server_metrics(self, start, end):
        """
        Pull the server metrics from New Relic and post them to the WF proxy.

        Arguments:
        start - the start datetime object
        end - the end datetime object
        """

        if (not self.config.include_servers or
                utils.CANCEL_WORKERS_EVENT.is_set()):
            return

        self.logger.info('Retrieving server metrics ...')
        servers = self.call_api('/servers.json')[0]
        for server in servers['servers']:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                return

            server_id = server['id']
            server_name = server['name']
            tags = {
                'server_id': server_id,
                'server_name': server_name
            }
            if (self.config.include_server_summary and
                    'summary' in server):
                summary = server['summary']
                for key, value in summary.iteritems():
                    if utils.CANCEL_WORKERS_EVENT.is_set():
                        break
                    metric_name = ('servers/%s/%s' % (server_name, key))
                    self.send_metric(self.proxy, metric_name, value, 'newrelic',
                                     server['last_reported_at'], tags,
                                     self.config.get_value_to_send, self.logger)
            self.send_metrics_for_server(server_id, server_name, start, end)

    def _application_metrics(self, start, end):
        """
        Pull the app metrics from New Relic and post them to the WF proxy
        Arguments:
        start - the start datetime object
        end - the end datetime object
        """

        if (not self.config.include_application_summary and
                not self.config.include_host_app_summary and
                not self.config.include_hosts):
            return

        query_string = None
        if self.config.application_ids:
            query_string = {
                'filter[ids]': ','.join(self.config.application_ids)
            }

        args = (start, end)
        self.call_paginated_api('/applications.json', query_string,
                                self._handle_applications_response, args)

    #pylint: disable=too-many-branches
    def _handle_applications_response(self, response, start, end):
        """
        Function that handles each page response that is returned from the
        /applications.json request
        Arguments:
        response - the page's response
        start - the start datetime object
        end - the end datetime object
        """

        if not response or 'applications' not in response:
            return

        for app in response['applications']:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                return
            self.logger.info('Retrieving %s - %s (app: %s)',
                             str(start), str(end), app['name'])
            if not app['reporting']:
                continue

            app_id = app['id']
            app_name = app['name']
            tags = {
                'app_id': app_id,
                'app_name': app_name
            }
            if self.config.include_application_summary:
                self.logger.info('Retrieving application summary (%s)...',
                                 app['last_reported_at'])
                summary = app['application_summary']
                for key, value in summary.iteritems():
                    if utils.CANCEL_WORKERS_EVENT.is_set():
                        break
                    metric_name = 'apps/%s/%s' % (app_name, key)
                    self.send_metric(self.proxy, metric_name, value,
                                     'newrelic', app['last_reported_at'],
                                     tags, self.config.get_value_to_send,
                                     self.logger)

                if 'end_user_summary' in app:
                    summary = app['end_user_summary']
                    for key, value in summary.iteritems():
                        if utils.CANCEL_WORKERS_EVENT.is_set():
                            break
                        metric_name = 'apps/%s/enduser/%s' % (app_name, key)
                        self.send_metric(self.proxy, metric_name, value,
                                         'newrelic', app['last_reported_at'],
                                         tags, self.config.get_value_to_send,
                                         self.logger)

            if ((self.config.include_hosts or
                 self.config.include_host_app_summary) and
                    not utils.CANCEL_WORKERS_EVENT.is_set()):

                for host_id in app['links']['application_hosts']:
                    if utils.CANCEL_WORKERS_EVENT.is_set():
                        break
                    self.send_metrics_for_host(app_id, app_name,
                                               host_id, start, end)

    #pylint: disable=too-many-branches
    def _execute(self):
        """
        Makes API calls to New Relic on behalf of the configured user and
        reports metrics to configured endpoint.
        """

        try:
            self.init_proxy()
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

            # if the time is more than 10 minutes, NR will make the sample size
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

                # get the application metrics
                self._application_metrics(curr_start, curr_end)

                # get the servers
                self._server_metrics(curr_start, curr_end)

                # save "last run time" and update curr_* variables
                self.config.set_last_run_time(curr_end)
                curr_start = curr_end
                curr_end = end
                curr_diff = curr_end - curr_start
                if (curr_diff.total_seconds() > 600 and
                        not utils.CANCEL_WORKERS_EVENT.is_set()):
                    time.sleep(30)

        finally:
            self.config.start_time = None
            self.config.end_time = None

    #pylint: disable=too-many-arguments
    #pylint: disable=too-many-locals
    #pylint: disable=too-many-branches
    def send_metrics_for_host(self, app_id, app_name, host_id, start, end):
        """
        Retrieves the metrics for the given host and sends them to configured
        endpoint.

        Arguments:
        app_id - The application's ID
        app_name - The application's name
        host_id - The host ID
        host_name - the host name
        start - the starting datetime object
        end - the ending datetime object
        """

        self.logger.info('Retrieving host %s summary metrics ...', str(host_id))

        app_host = self.call_api(
            '/applications/%s/hosts/%s.json' % (app_id, host_id))[0]
        if not app_host:
            return

        app_host = app_host['application_host']
        host_name = app_host['host']
        tags = {
            'app_id': app_id,
            'app_name': app_name
        }
        self.logger.debug('host: %s', host_name)
        if (self.config.include_host_app_summary and
                'application_summary' in app_host):
            summary = app_host['application_summary']
            for key, value in summary.iteritems():
                metric_name = 'apps/%s/%s' % (app_name, key)
                self.send_metric(self.proxy, metric_name, value, host_name,
                                 start.isoformat(), tags,
                                 self.config.get_value_to_send, self.logger)

        if not self.config.include_hosts:
            return

        self.logger.info('Retrieving host %s metrics ...', host_name)
        path = '/applications/%s/hosts/%s' % (app_id, host_id)

        # get the list of names from the config and by querying NR
        if self.config.fields:
            names = list(self.config.fields)
        else:
            names = []
        names.extend(self.get_metric_names_for_path(
            path, self.config.additional_fields))

        # now we have a list of metric names apply some filtering based
        # on the white and black list
        if self.config.fields_regex:
            for fieldname in names[:]:
                found = False
                for pattern in self.config.fields_regex_compiled:
                    if pattern.match(fieldname):
                        found = True
                        break
                if not found:
                    names.remove(fieldname)
        # black list ...
        if self.config.fields_blacklist_regex:
            self.logger.debug('Checking field names against black list')
            for fieldname in names[:]:
                found = False
                for pattern in self.config.fields_blacklist_regex_compiled:
                    if pattern.match(fieldname):
                        found = True
                        break
                if found:
                    names.remove(fieldname)

        self.logger.debug('%d Metric names for path %s:\n%s',
                          len(names), path, str(names))
        self.get_metrics_for_path(path, names, start, end, host_name, tags)

    def send_metrics_for_server(self, server_id, server_name, start, end):
        """
        Retrieves the metrics for the given server and sends them to configured
        endpoint.

        Arguments:
        server_id - The server's ID
        start - the starting datetime object
        end - the ending datetime object
        """

        path = '/servers/%s' % (server_id)
        fields = self.get_metric_names_for_path(path, [])
        tags = {
            'server_id': server_id,
            'server_name': server_name
        }
        self.get_metrics_for_path(path, fields, start, end, server_name, tags)

    #pylint: disable=too-many-arguments
    def get_metrics_for_path(self, path, fields_to_get, start, end,
                             src_name, tags):
        """
        Get metrics from the NR API and send them to Wavefront.

        Arguments:
        path - API path
        fields_to_get - the list of field names to retrieve
        start -
        end -
        src_name -
        tags
        """

        if utils.CANCEL_WORKERS_EVENT.is_set():
            return

        self.logger.debug('Getting metrics for path %s (src=%s, tags=%s)',
                          path, src_name, str(tags))

        # there is a limit on the size of the query string.  we pick a
        # max number of metric names to get on each request and loop
        # until we've got all metric values.
        # fields_to_get_temp contains all the remaining metric names
        # to get. as each group of metric names is retrieved, they are
        # removed (see end of loop).
        # during each iteration, get the first X (max) metric values.
        fields_to_get_temp = list(fields_to_get)

        function_pointers = []
        while len(fields_to_get_temp) > 0:
            query_string = {
                'from': start.isoformat(),
                'to': end.isoformat(),
                'names[]': fields_to_get_temp[0:self.config.max_metric_names],
                'raw': True,
                'summarize': False
            }
            del fields_to_get_temp[0:self.config.max_metric_names]

            function_pointers.append((self.response_worker,
                                      (path, query_string, src_name, tags)))

        self.logger.debug('Metrics for path %s: work queue has %d items',
                          path, len(function_pointers))
        parallel_process_and_wait(function_pointers, self.config.workers,
                                  self.logger)

    def response_worker(self, path, query_string, src_name, tags):
        """
        Worker that runs in a separate thread to execute the call_api call
        and process the response.
        """

        response = self.call_api(path + '/metrics/data.json', query_string)[0]
        if not response or 'metric_data' not in response:
            self.logger.warning('%s: response does not contain metric_data',
                                path)
            return

        # need to get a new writer for each thread (create a new socket)
        writer = NewRelicCommand.get_writer_from_config(self.config)

        try:
            # parse and collect the metrics
            metrics = response['metric_data']['metrics']
            for metric_detail in metrics:
                if utils.CANCEL_WORKERS_EVENT.is_set():
                    break
                name = metric_detail['name']
                for time_slice in metric_detail['timeslices']:
                    for metric, value in time_slice['values'].iteritems():
                        if utils.CANCEL_WORKERS_EVENT.is_set():
                            break
                        metric_name = '%s/%s' % (name, metric)
                        NewRelicCommand.send_metric(
                            writer, metric_name, value, src_name,
                            time_slice['to'], tags,
                            self.config.get_value_to_send)
        finally:
            writer.stop()
