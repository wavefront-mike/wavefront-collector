"""
This is common code used by the New Relic plugin.
"""

import datetime
import json
import logging
import numbers
import sys
import time

import urllib2
import urlparse
import dateutil

from wavefront.metrics_writer import WavefrontMetricsWriter
from wavefront import command
from wavefront import utils

# http://bugs.python.org/issue7980
# bug indicates that datetime.datetime.strptime() must be called once before
# multiple threads are started that use this function.
datetime.datetime.strptime('2016-04-27T13:30:15+00:00',
                           '%Y-%m-%dT%H:%M:%S+00:00')

class NewRelicCommand(command.Command):
    """
    Base class for all New Relic command objects
    """

    def __init__(self, **kwargs):
        super(NewRelicCommand, self).__init__(**kwargs)
        self.config = None
        self.proxy = None

    def init_proxy(self):
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

    #pylint: disable=too-many-arguments
    #pylint: disable=bare-except
    @staticmethod
    def send_metric(writer, name, value, host, timestamp, tags=None,
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
                writer.transmit_metric('newrelic.' + utils.sanitize_name(name),
                                       value, int(timestamp), host, tags)
                break
            except:
                attempts = attempts + 1
                logger.warning('Failed to transmit metric %s: %s',
                               name, str(sys.exc_info()))
                if not utils.CANCEL_WORKERS_EVENT.is_set():
                    time.sleep(1)

    #pylint: disable=line-too-long
    def call_paginated_api(self, path, query_string, callback, callback_args):
        """
        Calls the New Relic API that contains the pagination information
        in the response and loops over all pages returning a structured
        response with each page having its own key.
        Expects to find a Link header in the response that has page details
        contained within it.  Something like this:
        HTTP/1.1 200 OK
        Link: <https://api.newrelic.com/v2/applications/13812111/metrics.json?page=1>; rel="first", <https://api.newrelic.com/v2/applications/13812111/metrics.json?page=1>; rel="prev", <https://api.newrelic.com/v2/applications/13812111/metrics.json?page=3>; rel="next", <https://api.newrelic.com/v2/applications/13812111/metrics.json?page=23>; rel="last"

        Arguments:
        path - the path of the API
        query_string - the query string (optional)
        callback - the function handling each page's response
        callback_args - the args to pass to the page callback function
        """

        full_response = []
        def get_page_response(page):
            """
            Gets a single page's response and calls the callback function
            Arguments:
            page - the page to retrieve
            Returns:
            The tuple of (json response, original urllib2 response object)
            """

            if query_string:
                page_query_string = query_string.copy()
            else:
                page_query_string = {}
            page_query_string['page'] = page

            tpl = self.call_api(path, page_query_string)
            if utils.CANCEL_WORKERS_EVENT.is_set():
                return tpl

            if callback:
                args = (tpl[0], ) + callback_args
                callback(*args)
            else:
                full_response.append(tpl[0])
            return tpl

        # get the first page and see if there are more by inspecting header
        tpl = get_page_response(1)
        if utils.CANCEL_WORKERS_EVENT.is_set():
            return full_response

        link = self.parse_link_header(tpl[1].info().getheader('Link'))

        # build a list of function pointers - one per page
        function_pointers = []
        for page in range(2, link['last'] + 1):
            function_pointers.append((get_page_response, (page,)))

        utils.parallel_process_and_wait(function_pointers, self.config.workers,
                                        self.logger)
        # empty unless callback is None
        return full_response

    def call_api(self, path, query_string=None):
        """
        Calls the New Relic API in a retry loop until no error or limit
        is reached

        Arguments:
        path - the path of the API
        query_string - the query string (optional)

        Returns:
        Tuple: JSON object parsed from the string returned by the URL and the
        original HTTP response object.
        """

        attempts = 0
        sleep_time = 5
        while attempts < 5 and not utils.CANCEL_WORKERS_EVENT.is_set():
            try:
                return self._call_api(path, query_string)
            except urllib2.HTTPError, err:
                if err.code == 500:
                    attempts = attempts + 1
                    if not utils.CANCEL_WORKERS_EVENT.is_set():
                        time.sleep(sleep_time)
                        sleep_time = sleep_time * 2
                    else:
                        return (None, None)
                else:
                    raise

            except ValueError:
                attempts = attempts + 1
                if not utils.CANCEL_WORKERS_EVENT.is_set():
                    time.sleep(sleep_time)
                    sleep_time = sleep_time * 2
                else:
                    return (None, None)

        return (None, None)


    def _call_api(self, path, query_string=None):
        """
        Calls the New Relic API and parses response as JSON

        Arguments:
        path - the path of the API
        query_string - the query string (optional)

        Returns:
        Tuple: JSON object parsed from the string returned by the URL and the
        original HTTP response object.
        """

        # build the URL
        url = self.config.api_endpoint + path
        self.logger.debug('%s', url)
        if query_string:
            url = '%s?%s' % (url, utils.urlencode_utf8(query_string))

        if self.config.api_log_path:
            with open(self.config.api_log_path, 'a') as log_fd:
                log_fd.write(url + '\n')

        # create the request object
        req = urllib2.Request(url=url)
        req.add_header('Accept', 'application/json')
        req.add_header(self.config.api_key_header_name, self.config.api_key)

        try:
            response = urllib2.urlopen(req, timeout=30)
            json_response = json.load(response)

        except urllib2.HTTPError as http_err:
            self.logger.warning('Failed [%s]: %s', url, str(http_err))
            try:
                json_response = json.load(http_err)

            except:
                json_err = sys.exc_info()[1]
                self.logger.warning('Failed to load JSON [%s]: %s',
                                    url, str(json_err))
                raise ValueError(str(json_err))

        except urllib2.URLError as url_err:
            self.logger.warning('Failed [%s]: %s', url, str(url_err))
            raise ValueError(str(url_err))

        except BaseException as base_ex:
            self.logger.warning('Failed (1) [%s]: %s', url, str(base_ex))
            raise ValueError(str(base_ex))

        except:
            self.logger.warning('Failed [%s]: %s', url, str(sys.exc_info()))
            raise ValueError('Unknown failure with ' + url)

        if self.config.api_log_path:
            with open(self.config.api_log_path, 'a') as log_fd:
                log_fd.write('%s\n' % (str(json_response)))

        if 'error' in json_response:
            if 'title' in json_response['error']:
                self.logger.warning('%s\n%s', json_response['error']['title'],
                                    str(json_response))
                raise ValueError(json_response['error']['title'])
            else:
                self.logger.warning('%s\n%s', str(json_response['error']),
                                    str(json_response))
                raise ValueError(json_response['error'])

        return (json_response, response)

    @staticmethod
    def parse_link_header(link):
        """
        Parses the Link header and returns a dictionary with keys:
           first: the first page
           next: the next page
           last: the last page
           previous: the previous page

        All will be 0 if not set

        Arguments:
        link - the link header string

        Returns:
        dictionary
        """

        rtn = {
            'first': 0,
            'next': 0,
            'last': 0,
            'previous': 0
        }

        if not link:
            return rtn

        #  Link: <.../v2/applications/X/metrics.json?page=1>; rel="first",
        parts = link.split(', ')
        for part in parts:
            components = part.split('; ')
            url = components[0][1:-1]
            result = urlparse.parse_qs(urlparse.urlparse(url).query)
            page = int(result['page'][0])
            if components[1] == 'rel="first"':
                rtn['first'] = page
            elif components[1] == 'rel="prev"':
                rtn['previous'] = page
            elif components[1] == 'rel="last"':
                rtn['last'] = page
            elif components[1] == 'rel="next"':
                rtn['next'] = page

        return rtn
