"""
This module handles parsing the AWS Billing Reports (stored on S3 in .zip
or just plain .csv format) and creating metrics to be sent to the WF proxy.
"""

import ConfigParser
import datetime
import io
import os
import sys
import time
import traceback
import zipfile

import logging.config

import dateutil

from wavefront.aws_common import AwsBaseMetricsCommand, AwsBaseMetricsConfiguration
from wavefront import utils

#pylint: disable=too-few-public-methods
#pylint: disable=too-many-instance-attributes
class AwsBillingConfiguration(AwsBaseMetricsConfiguration):
    """
    Configuration for billing
    """
    def __init__(self, config_file_path):
        super(AwsBillingConfiguration, self).__init__(
            config_file_path=config_file_path)

        self.enabled = self.getboolean('aws_billing', 'enabled', False)
        self.role_arn = self.get('aws_billing', 'role_arn', None)
        self.role_external_id = self.get(
            'aws_billing', 'external_id', None)
        self.billing_thread_names = self.getlist(
            'aws_billing', 'billing_threads', [])
        self.ec2_tag_keys = self.getlist('aws_billing', 'ec2_tag_keys', [])
        self.billing_threads = []
        for name in self.billing_thread_names:
            section = 'billing-' + name
            self.billing_threads.append(
                AwsBillingDetailThreadConfiguration(self, section))

    def validate(self):
        """
        Validation of configuration
        """

        pass

    def get_region_config(self, _):
        """
        Gets the configuration for cloudwatch for the given region
        Arguments:
        region - the name of the region
        """

        return self

#pylint: disable=too-few-public-methods
#pylint: disable=too-many-instance-attributes
class AwsBillingDetailThreadConfiguration(object):
    """
    Configuration for a billing detail section in the configuration file
    """

    def __init__(self, config, section_name):
        super(AwsBillingDetailThreadConfiguration, self).__init__()

        self.config = config
        self.section_name = section_name
        self.last_run_time_section = section_name
        self.tmp_dir = self.config.get(section_name, 'tmp_dir', '/tmp/')
        self.namespace = self.config.get(section_name, 'namespace', None)
        self.enabled = self.config.getboolean(section_name, 'enabled', False)
        self.region = self.config.get(section_name, 's3_region', None)
        self.bucket = self.config.get(section_name, 's3_bucket', None)
        self.prefix = self.config.get(section_name, 's3_prefix', None)
        self.header_row_index = int(
            self.config.get(section_name, 'header_row_index', 1))
        self.dimensions = self._build_table(
            self.config.getlist(section_name, 'dimension_column_names', []))
        self.metrics = self._build_table(
            self.config.getlist(section_name, 'metric_column_names', []))
        self.source_names = self.config.getlist(section_name, 'source_names', [])
        self.dates = self._build_table(
            self.config.getlist(section_name, 'date_column_names', []), '|')
        self.duration = self.config.getlist(section_name, 'duration_column_names', [])
        self.instance_id_columns = self.config.getlist(
            section_name, 'instance_id_column_names', [])
        self.delay = int(self.config.get(section_name, 'delay', 3600))
        self.record_id_column = self.config.get(
            section_name, 'record_id_column_name', None)
        self.maximum_number_of_rows = int(self.config.get(
            section_name, 'maximum_number_of_rows', 0))
        self.sleep_after_rows = int(self.config.get(
            section_name, 'sleep_after_rows', 0))
        self.sleep_ms = float(self.config.get(
            section_name, 'sleep_ms', 0.0)) / 1000

    @staticmethod
    def _build_table(lst, delimiter=':'):
        """
        Build a dictionary from a list of delimiter-separated key-value pairs
        Arguments:
        lst - list of strings
        delimiter - delimiter between components of each string in the lst

        Returns:
        dictionary with the key being the string on the left side of
        the delimiter and the value of the dictionary key being the string
        on the right side
        """

        rtn = {}
        if lst:
            for item in lst:
                parts = item.split(delimiter)
                if len(parts) == 1:
                    rtn[parts[0]] = parts[0]
                elif len(parts) == 2:
                    rtn[parts[0]] = parts[1]

        return rtn

    def get_last_record_id(self, curr_month):
        """
        Gets the last record id for the given month
        """
        return self.config.get(
            self.section_name, 'last_record_id_' + curr_month, None)

    def set_last_record_id(self, curr_month, record_id):
        """
        Sets the last record id read

        Arguments:
        record_id - last record id
        """

        if not record_id:
            return

        self.config.output.set(
            self.section_name, 'last_record_id_' + curr_month, record_id)
        self.config.output.save()

class AwsBillingMetricsCommand(AwsBaseMetricsCommand):
    """
    Billing metrics command object.  Grabs metrics from billing CSV files.
    """

    def __init__(self, **kwargs):
        super(AwsBillingMetricsCommand, self).__init__(**kwargs)

    def _initialize(self, args):
        """
        Initialize this command

        Arguments:
        arg - the argparse parser object returned from argparser
        """

        self.config = AwsBillingConfiguration(args.config_file_path)
        self.config.validate()
        try:
            logging.config.fileConfig(args.config_file_path)
        except ConfigParser.NoSectionError:
            pass
        self.logger = logging.getLogger()

    def _process(self):
        """
        Processes the latest billing details CSV file.  A few helpful sites:
        http://www.dowdandassociates.com/products/cloud-billing/documentation/1.0/schema/
        http://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/detailed-billing-reports.html#reportstagsresources
        """

        utcnow = (datetime.datetime.utcnow()
                  .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))

        if utils.CANCEL_WORKERS_EVENT.is_set():
            return

        if not self.config.enabled:
            self.logger.info('Billing is disabled')
            return

        for config in self.config.billing_threads:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                break

            try:
                if config.enabled:
                    if config.get_last_run_time():
                        diff = utcnow - config.get_last_run_time()
                        if diff.total_seconds() <= config.delay:
                            self.logger.info('Not ready to run %s (last run at '
                                             '%s; expected delay interval is %ds)',
                                             config.section_name,
                                             str(config.get_last_run_time()),
                                             config.delay)
                            continue
                    if config.bucket == 'local':
                        self.logger.info('Running in local mode ...')
                        self._get_csv_from_local(config)

                    else:
                        self._get_csv_from_s3(config)
                    config.set_last_run_time(utcnow)
                else:
                    self.logger.info('Billing thread %s is disabled',
                                     config.section_name)

            #pylint: disable=bare-except
            except:
                self.logger.error('%s failed: %s', config.section_name,
                                  sys.exc_info()[1])
                traceback.print_exc()

    def _get_csv_from_local(self, config):
        """
        Opens a CSV file on the local machine
        Arguments:
        config - the AwsBillingDetailThreadConfiguration object
        """

        self.logger.info('Getting AWS billing details from local file system %s',
                         config.section_name)
        with open(config.prefix, 'r') as csvfd:
            csv_file = utils.CsvFile(csvfd, config.header_row_index)
            self.parse_csv(config, csv_file, 'local')

    #pylint: disable=too-many-locals
    #pylint: disable=too-many-branches
    #pylint: disable=too-many-statements
    def _get_csv_from_s3(self, config):
        """
        Opens a CSV file that matches the prefix in the S3 bucket.
        Arguments:
        config - the AwsBillingDetailThreadConfiguration object
        """

        self.logger.info('Getting AWS billing details from S3 for %s',
                         config.section_name)
        utcnow = (datetime.datetime.utcnow()
                  .replace(microsecond=0, tzinfo=dateutil.tz.tzutc()))

        s3cli = self.account.get_session(
            config.region, self.config.role_arn,
            self.config.role_external_id).client('s3')
        acct_id = self.account.get_account_id(self.config.role_arn)
        curr_month = utcnow.strftime('%Y-%m')
        prefix = (config.prefix
                  .replace('${account_id}', acct_id)
                  .replace('${date}', curr_month))

        # find the item in the s3 bucket
        response = s3cli.list_objects(Bucket=config.bucket, Prefix=prefix)
        if (not response or 'Contents' not in response or
                not response['Contents']):
            self.logger.warning('Billing details file [%s] not found in %s\n%s',
                                prefix, config.bucket, str(response))
            return

        # open the item in S3
        key = None
        zipped = False
        for s3file in response['Contents']:
            if s3file['Key'][-8:] == '.csv.zip':
                key = s3file['Key']
                zipped = True
                break

            if s3file['Key'][-4:] == '.csv':
                key = s3file['Key']
                zipped = False

        if not key:
            self.logger.warning('Unable to find billing file [%s] in %s',
                                prefix, config.bucket)
            return

        try:
            response = s3cli.get_object(Bucket=config.bucket, Key=key)
            csv_contents = io.BytesIO(response['Body'].read())

            filename = None
            if zipped:
                self.logger.info('Unzipping %s ...', key)
                with zipfile.ZipFile(csv_contents, 'r') as zipref:
                    key = key[0:-4] # remove .zip
                    filename = config.tmp_dir + key
                    zipref.extractall(config.tmp_dir)

                if utils.CANCEL_WORKERS_EVENT.is_set():
                    return
                with open(filename, 'r') as csvfd:
                    csv_file = utils.CsvFile(csvfd, config.header_row_index)
                    self.parse_csv(config, csv_file, curr_month)

            else:
                csv_file = utils.CsvFile(csv_contents, config.header_row_index)
                self.parse_csv(config, csv_file, curr_month)

        finally:
            if filename and os.path.exists(filename):
                self.logger.info('Removing %s ...', filename)
                os.remove(filename)

    def parse_csv(self, config, csvreader, curr_month):
        """
        Parse the CSV contents and generate metrics.
        Arguments:
        config - the AwsBillingDetailThreadConfiguration object
        csvreader - utils.CsvFile object
        curr_month - Y-M
        """

        rows = 0
        record_id = None
        current_record_id = None
        if config.record_id_column:
            record_id = config.get_last_record_id(curr_month)
            self.logger.info('Skipping records until after record ID %s', record_id)

        # loop over all lines in the csv file after the header and
        # transmit the cost metric for each one
        #pylint: disable=bare-except
        for row in csvreader:
            if utils.CANCEL_WORKERS_EVENT.is_set():
                break

            try:
                if config.record_id_column and row[config.record_id_column]:
                    current_record_id = row[config.record_id_column]
                    if record_id and current_record_id != record_id:
                        continue
                    elif record_id and current_record_id == record_id:
                        record_id = None
                        continue
                    else:
                        record_id = None

                self._process_csv_row(row, config)

            except:
                self.logger.warning('Unable to process record (%s):\n\t%s',
                                    sys.exc_info()[1], str(row))
                traceback.print_exc()

            rows = rows + 1
            if config.maximum_number_of_rows:
                if rows >= config.maximum_number_of_rows:
                    self.logger.debug('Stopping after %d rows', rows)
                    break

            if config.sleep_after_rows and rows % config.sleep_after_rows == 0:
                self.logger.debug('Sleeping %0.2f', config.sleep_ms)
                time.sleep(config.sleep_ms)

        if current_record_id:
            self.logger.info('Recording last record id of %s for %s',
                             current_record_id, curr_month)
            config.set_last_record_id(curr_month, current_record_id)

    def _process_csv_row(self, row, config):

        # point tags
        point_tags = {}
        for header, point_tag_key in config.dimensions.iteritems():
            if row[header]:
                point_tags[point_tag_key] = row[header]

        # point tags from ec2 instance
        #pylint: disable=too-many-nested-blocks
        if config.instance_id_columns:
            found_instance = False
            for header in config.instance_id_columns:
                instance_id = row[header]

                # arn:aws:ec2:us-east-1:011750033084:instance/i-33ac36e5"
                if instance_id and instance_id[0:12] == 'arn:aws:ec2:':
                    parts = instance_id.split(':')
                    instance_id = parts[5].split('/')[1]
                    point_tags['region'] = parts[3]

                if not instance_id or instance_id[0:2] != 'i-':
                    continue
                for region in self.account.regions:
                    for sub_account in self.account.get_sub_accounts():
                        instances = sub_account.get_instances(region)
                        if instance_id in instances:
                            instance_tags = instances[instance_id]
                            for key, value in instance_tags.iteritems():
                                point_tags[key] = value
                            found_instance = True
                            break
                    if found_instance:
                        break

                if found_instance:
                    break

        # source names
        source, source_name = AwsBaseMetricsCommand.get_source(
            config.source_names, point_tags)
        if source_name in point_tags:
            del point_tags[source_name]

        # timestamp
        tstamp = None
        tstamp_col_values = []
        for header, date_fmt in config.dates.iteritems():
            if row[header]:
                tstamp_col_values.append(row[header])
                tstamp = utils.unix_time_seconds(
                    datetime.datetime.strptime(row[header], date_fmt))

        if not tstamp:
            self.logger.warning('Unable to find valid date in columns (%s) '
                                '|%s|.  Record is:\n\t%s',
                                ', '.join(config.dates.keys()),
                                ', '.join(tstamp_col_values),
                                str(row))
            return

        # calculate duration
        if config.duration and len(config.duration) == 2:
            start = config.duration[0].split('|')
            start_dt = datetime.datetime.strptime(row[start[0]],
                                                  start[1])
            start_tstamp = utils.unix_time_seconds(start_dt)

            end = config.duration[1].split('|')
            end_dt = datetime.datetime.strptime(row[end[0]], end[1])
            end_tstamp = utils.unix_time_seconds(end_dt)

            duration = end_tstamp - start_tstamp
        else:
            duration = 0

        # metric and value
        for header, metric_name in config.metrics.iteritems():
            if config.namespace:
                metric = config.namespace + '.' + metric_name
            else:
                metric = metric_name

            value = row[header]
            if not value:
                value = 0.0

            # send the metric to the proxy
            self.proxy.transmit_metric(metric, value, long(tstamp),
                                       source, point_tags)
            if duration:
                self.proxy.transmit_metric(metric + '.duration',
                                           duration, long(tstamp),
                                           source, point_tags)

