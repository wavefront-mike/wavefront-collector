#!/usr/bin/env python
"""
This is the top level script that runs "commands" for Wavefront.
In the longer term, the INSTALLED_COMMANDS constant should be dyanmically
generated from the commands currently installed.
"""

from __future__ import print_function

import ConfigParser
import importlib
import logging
import logging.config
import sys
import threading
import traceback

import argparse
import daemon
import daemon.pidfile
from wavefront import utils


# List of available commands to run.  This is currently hard-coded, but later
# could (and should) be auto-generated from the commands installed.
INSTALLED_COMMANDS = {
    'appdynamics': (
        'wavefront.appdynamics',
        'AppDMetricRetrieverCommand'
        ),
    'awsbilling': (
        'wavefront.awsbilling',
        'AwsBillingMetricsCommand'
        ),
    'awscloudwatch': (
        'wavefront.awscloudwatch',
        'AwsCloudwatchMetricsCommand'
        ),
    'newrelic': (
        'wavefront.newrelic',
        'NewRelicMetricRetrieverCommand'
        ),
    'systemchecker': (
        'wavefront.system_checker',
        'SystemCheckerCommand'
        )
    }

def parse_args():
    """
    Parse user arguments and return as parser object.
    """

    # there are 2 ways to configure this:
    # 1 - run a single command via the command line
    # 2 - run one or more commands via a configuration file

    parser = argparse.ArgumentParser(description='Wavefront command line tool')
    parser.add_argument('-c', help='Specify a configuration file',
                        dest='config')
    parser.add_argument('--daemon', action='store_true', default=False,
                        help='Run in background (default is false)')
    parser.add_argument('--out',
                        help=('The path to the file where stdout/stderr '
                              'should be redirected when running --daemon'))
    parser.add_argument('--pid',
                        help='The path to the PID file when running --daemon')
    parser.add_argument('--verbose', action='store_true', default=False,
                        help='More output')

    args, _ = parser.parse_known_args()
    if args.config:
        print('Reading configuration file %s ...' % (args.config))
        return WavefrontConfiguration(args.config, args)

    parser = argparse.ArgumentParser(description='Wavefront command line tool')
    subparsers = parser.add_subparsers(
        dest='command',
        help=('Available commands.  Use \'wavefront <command name> -h\' to '
              'get help on an individual command'))

    #pylint: disable=bare-except
    for command_name, details in INSTALLED_COMMANDS.iteritems():
        try:
            module = importlib.import_module(details[0])
        except:
            if args.verbose:
                print('failed loading %s: %s' %
                      (command_name, str(sys.exc_info())))
                traceback.print_exc()
            continue

        class_name = details[1]
        command = getattr(module, class_name)(name=command_name)
        subparser = subparsers.add_parser(command_name,
                                          help=command.get_help_text())
        command.add_arguments(subparser)

    parser.add_argument('--verbose', action='store_true', default=False,
                        help='More output')
    parser.add_argument('--daemon', action='store_true', default=False,
                        help='Run in background (default is false)')
    parser.add_argument('--out', default='./wavefront.out',
                        help=('The path to the file where stdout/stderr '
                              'should be redirected when running --daemon'))
    parser.add_argument('--pid', default='./wavefront.pid',
                        help='The path to the PID file when running --daemon')
    parser.add_argument('--delay', default='0', type=float,
                        help=('The number of seconds to delay between each '
                              'execution when running --daemon'))

    return parser.parse_args()

#pylint: disable=too-few-public-methods
class WavefrontThreadConfiguration(object):
    """
    Simple object to wrap the configuration items of a "thread" group in
    the wavefront.conf file
    """

    def __init__(self, config, config_group):
        self.command = config.get(config_group, 'command', None)
        args = config.getlist(config_group, 'args', '')
        self.verbose = config.verbose
        self.command_object = get_command_object(self.command)

        parser = argparse.ArgumentParser()
        self.command_object.add_arguments(parser)
        self.args, _ = parser.parse_known_args(args=args)
        self.args.verbose = self.verbose
        self.delay = int(config.get(config_group, 'delay', 0))
        self.args.delay = self.delay
        self.enabled = config.getboolean(config_group, 'enabled', True)

class WavefrontConfiguration(utils.Configuration):
    """
    Configuration class wrapping the wavefront configuration file
    """

    def __init__(self, config_file_path, command_line_args):
        super(WavefrontConfiguration, self).__init__(
            config_file_path=config_file_path)

        if command_line_args.daemon:
            self.daemon = command_line_args.daemon
        else:
            self.daemon = self.getboolean('global', 'daemon', False)
        self.verbose = self.getboolean('global', 'verbose', False)
        if command_line_args.out:
            self.out = command_line_args.out
        else:
            self.out = self.get('global', 'out', 'wavefront.out')
        if command_line_args.pid:
            self.pid = command_line_args.pid
        else:
            self.pid = self.get('global', 'pid', 'wavefront.pid')
        self.debug = self.getboolean('global', 'debug', False)

        names = self.getlist('global', 'threads', [])
        self.thread_configs = []
        for name in names:
            print('Loading thread %s' % (name.strip(),))
            name = 'thread-' + name.strip()
            self.thread_configs.append(WavefrontThreadConfiguration(self, name))

#pylint: disable=broad-except
def main():
    """
    Main function
    """

    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=logging.INFO)
    args = parse_args()
    if args.daemon:
        stdout = open(args.out, 'w+')
        print ('Running in background.  stdout/stderr being redirected to %s ' %
               (args.out))
        with daemon.DaemonContext(stdout=stdout, stderr=stdout,
                                  pidfile=daemon.pidfile.PIDLockFile(args.pid),
                                  working_directory='.'):
            execute_commands(args)

    else:
        execute_commands(args)

def execute_commands(args):
    """
    Executes all commands specified in the configuration file and command line

    Arguments:
    args - argparse object or WavefrontConfiguration
    """

    logger = logging.getLogger()
    utils.setup_signal_handlers(logger)
    if isinstance(args, WavefrontConfiguration):
        try:
            logging.config.fileConfig(args.config_file_path)
        except ConfigParser.NoSectionError:
            pass

        threads = []
        for conf in args.thread_configs:
            if not conf.enabled:
                logger.info('Skipping disabled command \'%s\'', conf.command)
                continue
            targs = (conf.command, conf.args,)
            thread = threading.Thread(target=execute_command, args=targs,
                                      name=conf.command)
            thread.daemon = True
            threads.append(thread)
            thread.start()

        threads_alive = threads[:]
        while threads_alive and not utils.CANCEL_WORKERS_EVENT.is_set():
            for thread in threads:
                if thread.is_alive():
                    thread.join(1)
                elif thread in threads_alive:
                    threads_alive.remove(thread)

    else:
        execute_command(args.command, args)

    logger.info('Done.')

def execute_command(command_name, args):
    """
    Executes a single command (could be in a separate thread or main thread)

    Arguments:
    args - argparse object or WavefrontConfiguration
    """

    try:
        command_object = get_command_object(command_name)
        command_object.verbose = args.verbose
        command_object.execute(args)

    except Exception as command_err:
        if args is not None and args.verbose:
            raise
        print('Failed to execute command "%s": %s' %
              (command_name, str(command_err)))

def get_command_object(command_name):
    """
    Gets the command object from the command name
    Arguments:
    command_name - the installed commands command key
    """

    if command_name in INSTALLED_COMMANDS:
        details = INSTALLED_COMMANDS[command_name]
        command_module = importlib.import_module(details[0])
        class_name = details[1]
        return getattr(command_module, class_name)(name=command_name)

    else:
        raise ValueError('Command ' + str(command_name) + ' not found')

if __name__ == '__main__':
    main()
