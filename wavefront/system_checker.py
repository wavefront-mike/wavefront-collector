#!/usr/bin/env python
"""
This is the system checker plugin for Wavefront.  It runs as part of the
wavefront integrations tool package.  It should be run on each host/system
where you want to check for things like core files, etc
"""

import ConfigParser
import fnmatch
import hashlib
import logging
import os
import os.path
import socket
import sys
import time

import wavefront_client
from wavefront.utils import Configuration
from wavefront_client.rest import ApiException
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

        self.cache_location = self.get('global', 'cache_dir', '/tmp')
        self.source_name = self.get('global', 'source_name',
                                    socket.gethostname())
        self.wf_api_key = self.get('wavefront', 'api_key', None)
        self.wf_api_base = self.get('wavefront', 'api_base',
                                    'https://metrics.wavefront.com')

        self.core_locations = self.getlist('cores', 'paths', [])
        self.core_patterns = self.getlist('cores', 'patterns', [])

        self.md5_files = self.getlist('md5', 'files', [])
        self.md5_hashes = self.getlist('md5', 'expected_hashes', [])

    def validate(self):
        """
        Validates the configuration values
        Throws:
        ValueError when md5 files length does not equal md5 hashes length
        """

        if len(self.md5_files) != len(self.md5_hashes):
            raise ValueError('md5.files must have the same number of items '
                             'as md5.expected_hashes')

    def set_expected_hash(self, index, hashval):
        """
        Sets the expected hash value for the given index

        Arguments:
        index - the index in the self.md5_hashes array to set (0 based)
        hashval - the md5 hash value to update to
        """

        self.md5_hashes[index] = hashval
        self.config.set('md5', 'expected_hashes', ','.join(self.md5_hashes))
        self.save()

class SystemCheckerCommand(command.Command):
    """
    System checker command class
    """

    def __init__(self, **kwargs):
        super(SystemCheckerCommand, self).__init__(**kwargs)
        self.config = None
        self.description = "System Checker"

    def _init_logging(self):
        self.logger = logging.getLogger()

    #pylint: disable=no-self-use
    def get_help_text(self):
        """
        Help text for this command.
        """

        return "System Checker for core dump files, md5 changes, etc"

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

        # configure wavefront api
        wavefront_client.configuration.api_key['X-AUTH-TOKEN'] = \
          self.config.wf_api_key
        wavefront_client.configuration.host = self.config.wf_api_base

    def _get_event_file(self, etype):
        """
        Gets the file where md5's are stored for the given event type
        Arguments:
        etype - event type

        Returns:
        Path to file where MD5 should be stored/searched
        """

        return os.path.join(self.config.cache_location, etype + '.cache')

    def _has_event(self, md5, etype):
        """
        Checks to see if the MD5 is in the file path

        Arguments:
        md5 - the hash key
        etype - event type

        Returns:
        True if MD5 is found in the file path; false o/w
        """

        file_path = self._get_event_file(etype)
        if not os.path.exists(file_path):
            return False

        self.logger.debug('Looking for "%s" in %s ...', md5, file_path)
        with open(file_path, 'r') as rmbr:
            for line in rmbr:
                if not line:
                    continue

                if md5 == line.strip():
                    self.logger.info('Already seen %s for %s', md5, etype)
                    return True

        return False

    def _remember_event(self, md5, etype):
        """
        Stores the MD5 of an event in the file path sepcified.

        Arguments:
        md5 - the hash key
        etype - event type for finding the file path
        """

        file_path = self._get_event_file(etype)
        with open(file_path, 'a') as rmbr:
            rmbr.write(md5)
            rmbr.write('\n')

    #pylint: disable=bare-except
    #pylint: disable=too-many-arguments
    def _send_event(self, md5, name, description, start, end, severity, etype):
        """
        Sends event to wavefront API

        Arguments:
        md5 - the md5 key for this event (will not resend)
        name - event name
        description -
        start -
        end -
        severity -
        etype - event type

        See Also:
        _remember_event()
        _has_event()

        Returns:
        True if successfully created event, false o/w
        """

        if md5 and self._has_event(md5, etype):
            return True

        events_api = wavefront_client.EventsApi()
        attempts = 0
        sleep_time = 1
        successful = False
        while attempts < 5 and not utils.CANCEL_WORKERS_EVENT.is_set():
            try:
                events_api.create_new_event(
                    name,
                    s=start,
                    e=end,
                    c=(start == end),
                    d=description,
                    h=list(self.config.source_name),
                    l=severity,
                    t=etype)
                successful = True
                break

            except ApiException as e:
                self.logger.warning('Failed to send event: %s (attempt %d)',
                                    e.reason, attempts+1)

            except:
                self.logger.warning('Failed to send event: %s (attempt %d)',
                                    str(sys.exc_info()), attempts+1)

            if not successful:
                attempts = attempts + 1
                if not utils.CANCEL_WORKERS_EVENT.is_set():
                    time.sleep(sleep_time)
                    sleep_time = sleep_time * 2

        if successful and md5:
            self._remember_event(md5, etype)

        return successful

    def _check_for_core_dumps(self):
        """
        Checks for core dump files in the configured paths
        """

        for path in self.config.core_locations:
            self.logger.info('Looking for core dump files in %s ...', path)
            for filename in os.listdir(path):
                for pattern in self.config.core_patterns:
                    if pattern:
                        if fnmatch.fnmatch(filename, pattern):
                            fullpath = os.path.join(path, filename)
                            self.logger.warning('Found core file %s', fullpath)
                            created = os.path.getctime(fullpath)
                            hashval = utils.hashfile(fullpath, hashlib.md5())
                            self._send_event(hashval, 'Core found',
                                             'Core file found at ' + fullpath,
                                             created, created, 'Warning',
                                             'Core')

    def _check_file_hash(self):
        """
        Checks the hash (md5 currently) for each file configured
        """

        index = 0
        for path in self.config.md5_files:
            self.logger.info('Checking MD5 for %s ...', path)
            hashval = utils.hashfile(path, hashlib.md5())
            expected_hashval = self.config.md5_hashes[index]
            if expected_hashval == 'first_run':
                self.config.set_expected_hash(index, hashval)
                continue

            if hashval != expected_hashval:
                modified = os.path.getmtime(path)
                self.logger.warning('[%s] MD5 mismatch. '
                                    'Expected: %s; Found: %s',
                                    path, expected_hashval, hashval)
                self._send_event(None, 'MD5 mismatch (' + path + ')',
                                 'MD5 mismatch (' + path + ')',
                                 modified, modified, 'Warning', 'MD5 mismatch')

            index = index + 1

    def _execute(self):
        """
        Starts looking for core dump files, etc as configured
        """

        self._check_for_core_dumps()
        self._check_file_hash()
