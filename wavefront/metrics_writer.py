"""
This module contains the classes that write metrics to their final endpoint.
"""
import socket
import threading

#pylint: disable=too-many-arguments
class MetricsWriter(object):
    """
    Writer for managing the socket connection to metrics receiver.
    """

    def __init__(self, host, port, dry_run=False):
        super(MetricsWriter, self).__init__()
        self.is_dry_run = dry_run
        self.host = host
        self.port = port
        self.sock = None

    def transmit_metric(self, name, value, timestamp, source, point_tags):
        """
        Transmit metric to the proxy.

        Arguments:
        name - the metric name (a.b.c)
        value - the numeric value for this metric
        timestamp - the timestamp for this metric
        source - this metric's host or source name
        point_tags - dictionary of key/value pairs
        """

        line = self._generate_line(name, value, timestamp, source, point_tags)
        if self.is_dry_run:
            thread_id = hex(threading.current_thread().ident)
            print '[{} {}:{}] {}'.format(thread_id, self.host, self.port, line)

        else:
            self.sock.sendall('%s\n' % line)

    def _generate_line(self, name, value, timestamp, source, point_tags):
        """
        This should be overridden by the derived classes.  Generates the
        metric put line for the writer.

        Arguments:
        name - the metric name (a.b.c)
        value - the numeric value for this metric
        timestamp - the timestamp for this metric
        source - this metric's host or source name
        point_tags - dictionary of key/value pairs
        """

        pass

    def start(self):
        """
        Connect and open the socket
        """

        if not self.is_dry_run:
            self.sock = socket.socket()
            self.sock.settimeout(10.0)
            self.sock.connect((self.host, self.port))

    def stop(self):
        """
        Stop and shutdown the open socket
        """

        if self.sock is not None and not self.is_dry_run:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()

    def __enter__(self):
        """
        Python with block enter routine
        """

        self.start()
        return self

    def __exit__(self, the_type, value, traceback):
        """
        Python with block exit routine
        """

        self.stop()


class WavefrontMetricsWriter(MetricsWriter):
    """
    This is the metrics writer for the Wavefront proxy format.
    """

    def __init__(self, host, port, dry_run=False):
        super(WavefrontMetricsWriter, self).__init__(host, port, dry_run)

    def _generate_line(self, name, value, timestamp, source, point_tags):
        """
        Generates the line in the Wavefront proxy format.
        """
        line = '{} {} {} source="{}"'.format(name, value, timestamp, source)
        if point_tags is not None:
            for tag_key, tag_value in point_tags.iteritems():
                line = line + ' "{}"="{}"'.format(tag_key.lower(), tag_value)
        return line

class OpenTSDBMetricsWriter(MetricsWriter):
    """
    This is the metrics writer for the OpenTSDB format.
    """

    def __init__(self, host, port, dry_run=False):
        super(OpenTSDBMetricsWriter, self).__init__(host, port, dry_run)

    def _generate_line(self, name, value, timestamp, source, point_tags):
        """
        Generates the line in the OpenTSDB format.
        put <metric> <timestamp> <value> <tagk1=tagv1[ tagk2=tagv2 ...]
        """
        line = 'put {} {} {} host="{}"'.format(name, timestamp, value, source)
        if point_tags is not None:
            for tag_key, tag_value in point_tags.iteritems():
                line = line + ' "{}"="{}"'.format(tag_key, tag_value)
        return line
