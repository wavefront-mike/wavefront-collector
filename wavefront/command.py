"""
Command base class and utility functions
"""

import gc
import logging
import time

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

    def _init_logging(self):
        """
        Initialize the logger.  Overwrite this to set the log to run from
        a separate configuration, etc.
        """

        pass

    def _parse_args(self, args):
        """
        Parses the command specific arguments out.

        Arguments:
        args - list of arguments
        """

        raise ValueError('command:parse_args() should be implemented '
                         'by subclass')

    def add_arguments(self, parser):
        """
        Adds this command's arguments to the argsparser object

        Arguments:
        parser - the subparser where arguments are added
        """

        raise ValueError('command:parse_args() should be implemented '
                         'by subclass')

    #pylint: disable=bare-except
    def execute(self, args):
        """
        Execute this command with the given arguments.

        Arguments:
        args - the command line arguments
        """

        self._parse_args(args)
        self._init_logging()
        while not utils.CANCEL_WORKERS_EVENT.is_set():
            try:
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
                self.logger.info('Executing %s ...', self.description)

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

    def output_verbose(self, msg):
        """
        Very simple function to output to stdout if verbose flag is set.

        Arguments:
        msg - the message to output
        """

        if self.verbose:
            print msg
