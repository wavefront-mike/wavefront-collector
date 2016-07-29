#!/usr/bin/env python
"""
This is the system checker plugin for Wavefront.  It runs as part of the
wavefront integrations tool package.  It should be run on each host/system
where you want to check for things like core files, etc
"""

import ConfigParser
import fnmatch
import hashlib
import httplib
import logging
import os
import os.path
import socket
import sys
import time

import wavefront_client
from wavefront_client.rest import ApiException
from wavefront.utils import Configuration
from wavefront import command
from wavefront import utils

# default location for the configuration file.
DEFAULT_CONFIG_FILE_PATH = '/opt/wavefront/etc/system_checker.conf'

#pylint: disable=too-many-instance-attributes
class SystemCheckerConfiguration(Configuration):
    """
    Configuration interface for system checker
    """

    def __init__(self, config_file_path):
        super(SystemCheckerConfiguration, self).__init__(
            config_file_path=config_file_path)

        # section: global
        self.cache_location = self.get('global', 'cache_dir', '/tmp')
        self.source_name = self.get('global', 'source_name',
                                    socket.gethostname())
        self.log_requests = self.getboolean('global', 'log_requests', False)
        self.ignore_ssl_cert_errors = self.getboolean(
            'global', 'ignore_ssl_cert_errors', False)

        # section: wavefront
        self.wf_api_key = self.get('wavefront', 'api_key', None)
        self.wf_api_base = self.get('wavefront', 'api_base',
                                    'https://metrics.wavefront.com')

        # section: find_files
        self.find_file_locations = self.getlist('find_files', 'paths', [])
        self.find_file_patterns = self.getlist('find_files', 'patterns', [])
        self.find_file_event_names = self.getlist(
            'find_files', 'event_names', [])

        # section: files_changed
        self.file_changed_files = self.getlist('file_changes', 'files', [])
        self.file_changed_event_names = self.getlist(
            'file_changes', 'event_names', [])

        # other instance variables (non-configuration)
        self.md5_config = None
        self.md5_hashes = None

        # initialize the cache directory
        self._init_cache()

    def _init_cache(self):
        """
        Initializes the cache directory
        """

        if not os.path.exists(self.cache_location):
            os.mkdir(self.cache_location)
            os.mkdir(os.path.join(self.cache_location, 'file-changes'))
            os.mkdir(os.path.join(self.cache_location, 'find-files'))

        self.md5_config = utils.Configuration(os.path.join(
            self.cache_location, 'file-changes', 'wf_md5_hashes.conf'), True)
        self.md5_hashes = {}
        if self.md5_config.has_section('hashes'):
            items = self.md5_config.config.items('hashes')
            for item in items:
                self.md5_hashes[item[0]] = item[1]

        # create directory to store hashes of files found
        for path in self.find_file_locations:
            cache_path = os.path.join(
                self.cache_location, 'find-files', utils.sanitize_name(path))
            if not os.path.exists(cache_path):
                os.makedirs(cache_path)

    def _get_file_found_cache_path(self, directory, filename, hashval):
        """
        Gets the file for a specific file and hash value combo for the cache
        directory.
        Arguments:
        directory - the directory where the file was found
        filename - the file name of the file found
        hashval - the md5 hash value of the file found
        """

        cache_path = os.path.join(
            self.cache_location, 'find-files', utils.sanitize_name(directory))
        sfilename = utils.sanitize_name(filename) + '_' + hashval
        return os.path.join(cache_path, sfilename)

    def has_file_found_cache_path(self, directory, filename, hashval):
        """
        Checks to see if the given file has already been reported.
        Arguments:
        directory - the directory where the file was found
        filename - the file name of the file found
        hashval - the md5 hash value of the file found
        """

        final_path = self._get_file_found_cache_path(
            directory, filename, hashval)
        return os.path.exists(final_path)

    def set_file_found(self, directory, filename, hashval):
        """
        Sets the file was found and its hash value.
        Arguments:
        directory - the directory where the file was found
        filename - the file name to the file found
        hashval - the md5 hash value of the file found
        """

        final_path = self._get_file_found_cache_path(
            directory, filename, hashval)
        with open(final_path, 'a'):
            os.utime(final_path, None)

    def validate(self):
        """
        Validates the configuration values
        Throws:
        ValueError when length of find files locations array does not equal
                   length of patterns and event names arrays
        """

        if len(self.find_file_locations) != len(self.find_file_patterns):
            raise ValueError('find_files:paths must have the same number of '
                             'elements as find_files:patterns')
        if len(self.find_file_locations) != len(self.find_file_event_names):
            raise ValueError('find_files:paths must have the same number of '
                             'elements as find_files:event_names')

    def set_expected_hash(self, filename, hashval):
        """
        Sets the expected hash value for the given index

        Arguments:
        filename - the name of the file
        hashval - the md5 hash value to update to
        """

        self.md5_hashes[filename] = hashval
        self.md5_config.set('hashes', filename, hashval)
        self.md5_config.save()

class SystemCheckerCommand(command.Command):
    """
    System checker command class
    """

    def __init__(self, **kwargs):
        super(SystemCheckerCommand, self).__init__(**kwargs)
        self.config = None
        self.description = "System Checker"

    #pylint: disable=no-self-use
    def get_help_text(self):
        """
        Help text for this command.
        """

        return ('System Checker for finding files matching a pattern, '
                'files that changed, etc.')

    def _initialize(self, arg):
        """
        Parses the arguments passed into this command.

        Arguments:
        arg - the argparse parser object returned from argparser

        Raises:
        ValueError - when config file is not provided
        """

        if 'config_file_path' not in arg:
            raise ValueError('--config parameter is required')

        self.config = SystemCheckerConfiguration(arg.config_file_path)
        self.config.validate()
        try:
            logging.config.fileConfig(arg.config_file_path)
        except ConfigParser.NoSectionError:
            pass

        # logger
        self.logger = logging.getLogger()
        if self.config.log_requests:
            httplib.HTTPConnection.debuglevel = 1

        # configure wavefront api
        wavefront_client.configuration.api_key['X-AUTH-TOKEN'] = \
          self.config.wf_api_key
        wavefront_client.configuration.host = self.config.wf_api_base
        wavefront_client.configuration.verify_ssl = (
            not self.config.ignore_ssl_cert_errors)

    #pylint: disable=bare-except
    #pylint: disable=too-many-arguments
    def _send_event(self, name, description, start, end, severity, etype):
        """
        Sends event to wavefront API

        Arguments:
        name - event name
        description -
        start -
        end -
        severity -
        etype - event type

        Returns:
        True if successfully created event, false o/w
        """

        events_api = wavefront_client.EventsApi()
        attempts = 0
        sleep_time = 1
        successful = False
        while attempts < 5 and not utils.CANCEL_WORKERS_EVENT.is_set():
            self.logger.info('%s Creating event %s', self.description, name)
            try:
                if start == end:
                    events_api.create_new_event(
                        name,
                        s=int(start),
                        c=True,
                        d=description,
                        h=[self.config.source_name, ],
                        l=severity,
                        t=etype)
                else:
                    events_api.create_new_event(
                        name,
                        s=int(start),
                        e=int(end),
                        c=False,
                        d=description,
                        h=[self.config.source_name, ],
                        l=severity,
                        t=etype)
                successful = True
                break

            except ApiException as api_ex:
                self.logger.warning('Failed to send event: %s (attempt %d)\n%s',
                                    api_ex.reason, attempts+1, api_ex.body)

            except:
                self.logger.warning('Failed to send event: %s (attempt %d)',
                                    str(sys.exc_info()), attempts+1)

            if not successful:
                attempts = attempts + 1
                if not utils.CANCEL_WORKERS_EVENT.is_set():
                    time.sleep(sleep_time)
                    sleep_time = sleep_time * 2

        return successful

    def _check_for_files_matching(self):
        """
        Checks for files matching a pattern in the configured paths
        """

        self.logger.info('Checking files in ' +
                         str(self.config.find_file_locations))
        for path in self.config.find_file_locations:
            self.logger.info('Looking for matching files in %s ...', path)
            if not os.path.exists(path):
                self.logger.warning('Path %s does not exist.', path)
                continue

            for filename in os.listdir(path):
                loc = 0
                for pattern in self.config.find_file_patterns:
                    if pattern and fnmatch.fnmatch(filename, pattern):
                        fullpath = os.path.join(path, filename)
                        hashval = utils.hashfile(fullpath, hashlib.md5())
                        if self.config.has_file_found_cache_path(
                                path, filename, hashval):
                            continue
                        self.logger.warning('[%s: %s] Found file "%s" matching '
                                            'pattern "%s"', self.description,
                                            path, filename, pattern)
                        created = os.path.getctime(fullpath)
                        name = self.config.find_file_event_names[loc]
                        if self._send_event(
                                name + ' found',
                                name + ' file found: ' + fullpath,
                                created,
                                created,
                                'Warning',
                                name):
                            self.config.set_file_found(path, filename, hashval)

                        loc = loc + 1

    def _check_for_files_changed(self):
        """
        Checks the hash (md5 currently) for each file configured
        """

        loc = 0
        for path in self.config.file_changed_files:
            try:
                self._check_file_hash(
                    path, self.config.file_changed_event_names[loc])
            except IOError as ioe:
                self.logger.error('Unable to check MD5 for %s: %s',
                                  path, str(ioe))
            loc = loc + 1

    def _check_file_hash(self, path, event_name):
        """
        Check a specific path's hash against its expected value
        Arguments:
        path - the full path to the file to check
        event_name - the event name to use when creating an event (on hash chng)
        """

        self.logger.info('Checking MD5 for %s ...', path)
        hashval = utils.hashfile(path, hashlib.md5())
        abspath = os.path.abspath(path)
        if (abspath not in self.config.md5_hashes or
                not self.config.md5_hashes[abspath]):
            # assume this is the first run
            self.config.set_expected_hash(abspath, hashval)

        else:
            expected_hashval = self.config.md5_hashes[abspath]

            if expected_hashval != hashval:
                modified = os.path.getmtime(path) * 1000
                self.logger.warning('[%s: %s] MD5 mismatch. '
                                    'Expected: %s; Found: %s',
                                    self.description, path, expected_hashval,
                                    hashval)
                self._send_event('File Change (' + path + ')',
                                 'File Change (' + path + ')',
                                 modified,
                                 modified,
                                 'Informational',
                                 event_name)

                # update the new expected hash to this value
                self.config.set_expected_hash(abspath, hashval)

    def _execute(self):
        """
        Starts looking for matching files, changed files, etc as configured
        """

        if not utils.CANCEL_WORKERS_EVENT.is_set():
            self._check_for_files_matching()
        if not utils.CANCEL_WORKERS_EVENT.is_set():
            self._check_for_files_changed()
