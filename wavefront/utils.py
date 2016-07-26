"""
Utility functions
"""

import ConfigParser
import csv
import datetime
import os.path
import re
import signal
import sys
import threading
import traceback
import urllib

import dateutil
import dateutil.tz

EPOCH = (datetime.datetime.utcfromtimestamp(0)
         .replace(tzinfo=dateutil.tz.tzutc()))
def unix_time_seconds(date_in):
    """
    Convert a datetime into unix epoch seconds
    Arguments:
    date_in - the datetime object to convert. This must have a tz = UTC
    """
    if not date_in.tzinfo or date_in.tzinfo != dateutil.tz.tzutc():
        date_in = date_in.replace(tzinfo=dateutil.tz.tzutc())
    return (date_in - EPOCH).total_seconds()

def urlencode_utf8(params):
    """
    Encode with utf8 characters.
    See: http://stackoverflow.com/a/8152242
    """
    if hasattr(params, 'items'):
        params = params.items()
    encoded = []
    for key, value in params:
        key = urllib.quote_plus(key.encode('utf8'), safe='/')
        if isinstance(value, list):
            for item in value:
                if isinstance(item, basestring):
                    item = urllib.quote_plus(item.encode('utf8'), safe='/')
                encoded.append('%s=%s' % (key, item))
            continue

        if isinstance(value, basestring):
            value = urllib.quote_plus(value.encode('utf8'), safe='/')

        encoded.append('%s=%s' % (key, value))

    return '&'.join(encoded)

class Configuration(object):
    """
    Base class for configurations that read from an INI file
    """

    def __init__(self, config_file_path, create_if_not_exist=False):
        super(Configuration, self).__init__()
        if not os.path.exists(config_file_path) and not create_if_not_exist:
            raise ValueError('Configuration file %s does not exist' %
                             (config_file_path))
        self.config_file_path = config_file_path
        self.config = ConfigParser.ConfigParser()
        self.config.read(config_file_path)

    def has_section(self, section):
        """
        Checks to see if the given section exists
        """
        try:
            self.config.get(section, "test")
        except ConfigParser.NoOptionError:
            return True
        except ConfigParser.NoSectionError:
            return False

    def get(self, section, key, default_value, default_section=None):
        """
        Gets a value from the configuration and returns the default if the
        section or key does not exist.

        Arguments:
        section - the section name
        key - the key in the section to retrieve
        default_value - the default value to return when section/key not found
        """

        try:
            value = self.config.get(section, key)
        except ConfigParser.NoOptionError:
            value = None
        except ConfigParser.NoSectionError:
            value = None


        if value is None:
            if default_section:
                return self.get(default_section, key, default_value, None)
            else:
                return default_value
        else:
            return value

    def getdate(self, section, key, default_value, default_section=None):
        """
        Gets a value from the configuration and returns the default if the
        section or key does not exist.  Assumes the value is stored as a
        string that is parseable by dateutil.parser.parse()

        Arguments:
        section - the section name
        key - the key in the section to retrieve
        default_value - the default value to return when section/key not found
        """

        value = self.get(section, key, None)
        if value:
            return (dateutil.parser.parse(value)
                    .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))
        elif default_section:
            return self.getdate(default_section, key, default_value, None)
        else:
            return default_value

    def getboolean(self, section, key, default_value, default_section=None):
        """
        Gets a value from the configuration and returns the default if the
        section or key does not exist.

        Arguments:
        section - the section name
        key - the key in the section to retrieve
        default_value - the default value to return when section/key not found
        """

        try:
            value = self.config.getboolean(section, key)
        except ConfigParser.NoOptionError:
            value = None
        except ConfigParser.NoSectionError:
            value = None

        if value is None:
            if default_section:
                return self.getboolean(
                    default_section, key, default_value, None)
            else:
                return default_value
        else:
            return value

    def getlist(self, section, key, default_value, default_section=None,
                delimiter=',', trim=False):
        """
        Gets a value from the configuration and returns the default if the
        section or key does not exist.  Value is assumed to be comma-separated
        list of values.  Will return a list split by ','.

        Arguments:
        section - the section name
        key - the key in the section to retrieve
        default_value - the default value to return when section/key not found
                        (assumed to be a list; not a string)
        trim - trim all items in the list
        """

        try:
            value = self.config.get(section, key)
            if value:
                value = value.split(delimiter)
        except ConfigParser.NoOptionError:
            value = None
        except ConfigParser.NoSectionError:
            value = None

        if value is None:
            if default_section:
                value = self.getlist(default_section, key, default_value, None)
            else:
                value = default_value

        if trim:
            return map(str.strip, value)
        else:
            return value

    def set(self, section, key, value, create_section=True):
        """
        Sets the value in the given section.  Creates the section if it does
        not exist.
        Arguments:
        section - the section name
        key - the key in the section to set
        value - the value to set
        create_section - create section if it does not exist?
        """

        try:
            self.config.set(section, key, value)
        except ConfigParser.NoSectionError as nosection:
            if create_section:
                self.config.add_section(section)
                self.config.set(section, key, value)
            else:
                raise nosection

    def save(self):
        """
        Save the current configuration to disk.
        """

        with open(self.config_file_path, 'w') as configfile:
            self.config.write(configfile)

def sanitize_name(_name, replace_map=None):
    """
    Replaces characters that are not supported
    default list:
    '.'  => _
    '//' => .
    '/'  => .
    '*'  => all
    r[^a-zA-Z-_0-9.] => _

    Arguments:
    _name - the name to sanitize

    Returns:
    Sanitized name
    """

    if not replace_map:
        replace_map = [
            {'*': 'all'},
            {'.': '_'},
            {'//': '.'},
            {'/': '.'}
        ]

    # see http://stackoverflow.com/a/27086669 for details on performance
    # of various methods of doing this
    name = _name.lower()
    for items in replace_map:
        for search, replace in items.iteritems():
            name = name.replace(search, replace)
    name = re.sub(r'[^a-z\-_0-9\.]', '_', name)
    return name

# Mapping for product names found in the CSV file to the metric prefix name
PRODUCT_NAME_TO_PREFIX = {
    'AmazonCloudWatch': 'cloudwatch',
    'Amazon DynamoDB': 'dynamodb',
    'Amazon Elastic Compute Cloud': 'ec2',
    'Amazon Elastic File System': 'efs',
    'Amazon Route 53': 'route53',
    'Amazon Simple Email Service': 'ses',
    'Amazon Simple Notification Service': 'sns',
    'Amazon Simple Queue Service': 'sqs',
    'Amazon Simple Storage Service': 's3',
    'Amazon Virtual Private Cloud': 'vpc',
    'AWS CloudHSM': 'cloudhsm',
    'AWS CloudTrail': 'cloudtrail',
    'AWS Config': 'config',
    'AWS Direct Connect': 'directconnect',
    'AWS Key Management Service': 'kms'
}

def get_aws_product_short_name(product):
    """
    Given a product name (e.g., "AWS CloudTrail"), return the metric
    name prefix for it (e.g., "cloudtrail")
    """

    if product in PRODUCT_NAME_TO_PREFIX:
        return PRODUCT_NAME_TO_PREFIX[product]
    else:
        return product.replace(' ', '')

#pylint: disable=too-few-public-methods
class LockedIterator(object):
    """
    thread-safe iterator
    """

    def __init__(self, iterator):
        self.lock = threading.Lock()
        self.iterator = iterator.__iter__()

    def __iter__(self):
        return self

    def next(self):
        """
        Get the next item in the iterator.
        Returns:
        The next item in the iteration
        Throws:
        StopIterator if next not found
        """

        self.lock.acquire()
        try:
            return self.iterator.next()
        finally:
            self.lock.release()

CANCEL_WORKERS_EVENT = threading.Event()
def parallel_process_and_wait(iterator, workers, logger=None):
    """
    Process an iterator of function pointers in parallel using the number
    of worker threads provided in the "workers" argument.
    Work is handed off to the 'worker' function in each new thread.
    Will wait for all threads to complete before returning

    Arguments:
    iterator - an iterable list of items to be passed to the worker routine
               each item should be a tuple of (function, (args))
    workers - number of workers (threads)
    """
    locked_iterator = LockedIterator(iterator)

    # start the threads
    group = []
    for _ in range(workers):
        thread = threading.Thread(target=worker,
                                  args=(locked_iterator, logger))
        thread.daemon = True
        thread.start()
        group.append(thread)

    # wait for all threads to finish
    # this while loop is here with a .join(timeout) because sometimes
    # a few threads seem to get "stuck" so we added a way to get debug
    # information every 60 seconds.
    iterations = 0
    active = 1
    while active and group and not CANCEL_WORKERS_EVENT.is_set():
        iterations = iterations + 1
        active = 0
        for thread in group:
            thread.join(60.0)
            if thread.is_alive():
                active = active + 1

        if logger and active:
            logger.debug('%d active thread(s) of %d total threads remaining',
                         active, len(group))
            if iterations % 5 == 0:
                dump_stack_traces(logger)

#pylint: disable=bare-except
def worker(locked_iterator, logger=None):
    """
    Worker for each thread created in parallel_process_and_wait()
    Arguments:
    locked_iterator - LockedIterator (thread-safe) iterator
    logger - optional logger object
    """

    while not CANCEL_WORKERS_EVENT.is_set():
        try:
            call_details = locked_iterator.next()
            call_details[0](*call_details[1])

        except StopIteration:
            break

        except:
            if logger:
                logger.exception('Failed to run thread worker')

            break

#pylint: disable=unused-argument
def script_debug(signalnum, frame):
    """
    Dump stack traces
    """

    dump_stack_traces(None)

#pylint: disable=unused-argument
def interrupt_signal_handler(signalnum, frame):
    """
    Function that gets called when SIGINT signal is sent
    """

    print 'Stopping running threads ...'
    # set the event so all worker threads will know to stop
    CANCEL_WORKERS_EVENT.set()

def setup_signal_handlers(logger):
    """
    Registers handlers for SIGINT
    """

    signal.signal(signal.SIGINT, interrupt_signal_handler)
    signal.signal(signal.SIGTERM, interrupt_signal_handler)
    signal.signal(signal.SIGUSR1, script_debug)
    if logger:
        logger.info('Signal handlers attached')

#pylint: disable=protected-access
def dump_stack_traces(logger=None):
    """
    Prints stack traces of all threads
    """

    out = []
    out.append('Threads: %d\n' % (threading.active_count()))
    for thread_id, stack in sys._current_frames().items():
        out.append('\n# Thread %s:' % thread_id)
        for filename, lineno, name, line in traceback.extract_stack(stack):
            out.append('File: "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                out.append("  %s" % (line.strip()))

    if logger:
        logger.info('STACK TRACE:\n%s', '\n'.join(out))
    else:
        print 'STACK TRACE:\n%s' % ('\n'.join(out))

def hashfile(file_path, hasher, blocksize=65536):
    """
    See: http://stackoverflow.com/a/3431835
    """

    with open(file_path, 'r') as afile:
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
        return hasher.hexdigest()

class CsvFileRow(object):
    """
    Row from CsvFile
    """

    def __init__(self, csvfile, row):
        """
        """
        self.csvfile = csvfile
        self.row = row

    def __getitem__(self, name):
        if name not in self.csvfile.header_key_to_index:
            raise ValueError('%s not in %s' %
                             (name, str(self.csvfile.header_key_to_index)))
        index = self.csvfile.header_key_to_index[name]
        return self.row[index]

class CsvFile(object):
    """
    Simple interface to the csv.reader
    """

    def __init__(self, reader, header_row_index=1):
        """
        Construct this instance.
        Arguments:
        reader - see csv.reader() csvfile parameter definition
        """

        self.csvreader = csv.reader(reader)

        # build map for header name to index
        index = 0
        while index < header_row_index:
            header_row = self.csvreader.next()
            index = index + 1

        self.header_key_to_index = {}
        index = 0
        for name in header_row:
            self.header_key_to_index[name] = index
            index = index + 1

    def __iter__(self):
        return self

    #pylint: disable=missing-docstring
    def next(self):
        return CsvFileRow(self, self.csvreader.next())
