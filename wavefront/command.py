"""
Command base class and utility functions
"""

import datetime
import gc
import logging
import os.path
import time

import dateutil.tz

from wavefront import utils

#pylint: disable=unused-argument
#pylint: disable=no-self-use
class Command(object):
    """
    This is the base class of each command implemented.
    """

    def __init__(self, **kwargs):
        super(Command, self).__init__()

        self.verbose = False
        self.logger = logging.getLogger()
        if len(self.logger.root.handlers) > 0:
            fmt = logging.Formatter('%(levelname)s: %(thread)d %(message)s')
            self.logger.root.handlers[0].setFormatter(fmt)
        self.description = kwargs.get('description', 'Wavefront command')
        self.name = kwargs.get('name', 'wfcollector')

    def _initialize(self, args):
        """
        Initializes the command

        Arguments:
        args - list of arguments
        """

        raise ValueError('command:_initiailize() should be implemented '
                         'by subclass')

    def add_arguments(self, parser):
        """
        Adds this command's arguments to the argsparser object

        Arguments:
        parser - the subparser where arguments are added
        """

        default_config = '/opt/wavefront/etc/' + self.name + '.conf'
        parser.add_argument('--config',
                            dest='config_file_path',
                            default=default_config,
                            help='Path to configuration file')

    #pylint: disable=bare-except
    def execute(self, args):
        """
        Execute this command with the given arguments.

        Arguments:
        arg - the argparse parser object returned from argparser
        """

        self._initialize(args)
        while not utils.CANCEL_WORKERS_EVENT.is_set():
            try:
                self.logger.info('Executing %s ...', self.description)
                self._execute()

            except:
                self.logger.exception('Failed executing %s', self.description)

            if utils.CANCEL_WORKERS_EVENT.is_set():
                break

            if 'delay' not in args or not args.delay or args.delay <= 0:
                break

            gc.collect()
            if not utils.CANCEL_WORKERS_EVENT.is_set():
                self.logger.info('Sleeping for %ds ...', args.delay)
                time.sleep(args.delay)

    def _execute(self):
        """
        Override this in the subclass to perform the command.
        """
        raise ValueError('command:_execute() should be implemented by subclass')

    def get_help_text(self):
        """
        Gets the text to display for this command.
        """

        return ""

# pylint: disable=too-few-public-methods
class CommandConfiguration(utils.Configuration):
    """
    Base class for configurations of a command
    """

    def __init__(self, config_file_path, create_if_not_exist=False):
        super(CommandConfiguration, self).__init__(
            config_file_path=config_file_path,
            create_if_not_exist=create_if_not_exist)

        self.last_run_time_section = 'options'
        self.output_directory = None
        self.output = None

    def _setup_output(self, config):
        """
        Sets up the output directory and output file
        """

        self.output_directory = config.get('options', 'output_directory', None)

        if self.output_directory:
            if not os.path.exists(self.output_directory):
                os.makedirs(self.output_directory)

            output_file = (self.output_directory + '/' +
                           os.path.basename(self.config_file_path) + '.save')
        else:
            output_file = ('/tmp/' +
                           os.path.basename(self.config_file_path) + '.save')

        # try to touch the file to see if we have permission
        try:
            with open(output_file, 'a'):
                os.utime(output_file, None)
        except IOError:
            raise ValueError('Unable to write to output file ' + output_file)

        self.output = utils.Configuration(
            config_file_path=output_file,
            create_if_not_exist=True)

    def get_last_run_time(self, section_name=None):
        """
        Gets the last run time as a string
        """

        if section_name:
            return self.output.getdate(section_name, 'last_run_time', None)

        else:
            return self.output.getdate(
                self.last_run_time_section, 'last_run_time', None)

    def set_last_run_time(self, run_time, section_name=None, ignore_cancel=False):
        """
        Sets the last run time to the run_time argument.

        Arguments:
        run_time - the time when this script last executed successfully (end)
        """

        if not ignore_cancel and utils.CANCEL_WORKERS_EVENT.is_set():
            return

        if not run_time:
            run_time = (datetime.datetime.utcnow()
                        .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        if section_name:
            self.output.set(section_name, 'last_run_time',
                            run_time.isoformat())
        else:
            self.output.set(self.last_run_time_section, 'last_run_time',
                            run_time.isoformat())
        self.output.save()
