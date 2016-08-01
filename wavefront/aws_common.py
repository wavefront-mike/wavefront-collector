"""
This is a library for common code shared between the AWS Cloudwatch script
and the AWS Billing script commands.
"""

import datetime
import json
import os
import os.path

import boto3

from wavefront.metrics_writer import WavefrontMetricsWriter
from wavefront import command

# default configuration


# The directory where we should look for and store the cache
# files of instances and their tags.
CACHE_DIR = '/tmp'

#pylint: disable=too-many-instance-attributes
class AwsBaseMetricsConfiguration(command.CommandConfiguration):
    """
    Common Configuration file for this command
    """

    def __init__(self, config_file_path):
        super(AwsBaseMetricsConfiguration, self).__init__(
            config_file_path=config_file_path)

        self.writer_host = self.get('writer', 'host', '127.0.0.1')
        self.writer_port = int(self.get('writer', 'port', '2878'))
        self.is_dry_run = self.getboolean('writer', 'dry_run', True)

        self.aws_access_key_id = self.get('aws', 'access_key_id', None)
        self.aws_secret_access_key = self.get('aws', 'secret_access_key', None)
        self.regions = self.getlist('aws', 'regions', None, None, ',', True)
        self.sub_accounts = self.getlist('aws', 'sub_accounts', [])

        self._setup_output(self)

class AwsBaseMetricsCommand(command.Command):
    """
    Abstract base class for both AWS cloudwatch metrics and AWS billing metrics
    commands.
    """

    def __init__(self, **kwargs):
        super(AwsBaseMetricsCommand, self).__init__(**kwargs)

        self.account = None
        self.config = None
        self.proxy = None

    def _init_proxy(self):
        """
        Initializes the proxy writer
        """

        self.proxy = WavefrontMetricsWriter(self.config.writer_host,
                                            self.config.writer_port,
                                            self.config.is_dry_run)
        self.proxy.start()

    def _process(self):
        """
        Process this aws command (implemented by derived class)
        """

        pass

    def _execute(self):
        """
        Execute this command
        """

        self._init_proxy()
        self.account = AwsAccount(self.config, True)
        self._process()

    @staticmethod
    def get_source(source_names, point_tags, dimensions=None):
        """
        Determine the source from the point tags.
        Argument:
        source_names - the key names in priority order to use as source
        point_tags - all the point tags for this metric (dictionary)
        dimensions - the dimensions for this metric (list of objects)

        Returns:
        Tuple of (source value, key of the source of the source)
        """

        for name in source_names:
            if name[0:1] == '=':
                return (name[1:], None)

            if name in point_tags and point_tags[name]:
                return (point_tags[name], name)

            if dimensions:
                for dim in dimensions:
                    if dim['Name'] == name and dim['Value']:
                        return (dim['Value'], name)

        return (None, None)

class AwsAccount(object):
    """
    Represents the AWS account and all of its sub accounts
    """

    def __init__(self, config, load=False):
        super(AwsAccount, self).__init__()
        self.config = config
        self.regions = self.config.regions
        self.sub_accounts = []
        self.sessions = {}
        if load:
            for sub_account in self.get_sub_accounts():
                sub_account.load_ec2_instance_data()

    def get_sub_accounts(self):
        """
        Gets a list of sub accounts
        """
        if not self.sub_accounts:
            for sub_account in self.config.sub_accounts:
                self.sub_accounts.append(AwsSubAccount(self, sub_account))
        return self.sub_accounts

    def get_account_id(self, role_arn=None):
        """
        Gets the account id by either parsing it from the role ARN or by
        getting the currently logged in user's ARN and parsing from there.
        """

        if role_arn:
            arn = role_arn

        else:
            iam_client = self.get_session('us-east-1', None, None).client('iam')
            arn = iam_client.get_user()['User']['Arn']

        return arn.split(':')[4]

    def get_session(self, region, role_arn, external_id, check_cache=True):
        """
        Creates a new session object in the given region
        Arguments:
        region - the region name
        check_cache - True to check the cache before creating new session
        """

        if role_arn:
            if not external_id:
                raise ValueError('External ID is required for region ' +
                                 region + ' and role ARN ' + role_arn)
            cache_key = ':'.join([region, role_arn, external_id])
        else:
            cache_key = region

        access_key_id = self.config.aws_access_key_id
        secret_access_key = self.config.aws_secret_access_key
        if not check_cache or cache_key not in self.sessions:
            if role_arn:
                session = boto3.session.Session()
                client = session.client(
                    'sts',
                    region_name=region,
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key)
                role = client.assume_role(RoleArn=role_arn,
                                          ExternalId=external_id,
                                          RoleSessionName='wavefront_session')
                self.sessions[cache_key] = boto3.Session(
                    role['Credentials']['AccessKeyId'],
                    role['Credentials']['SecretAccessKey'],
                    role['Credentials']['SessionToken'],
                    region_name=region)

            else:
                self.sessions[cache_key] = boto3.Session(
                    region_name=region,
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key)

        return self.sessions[cache_key]

#pylint: disable=too-few-public-methods
class AwsSubAccountConfiguration(object):
    """
    Configuration for a specific sub account section in the INI file
    """

    def __init__(self, config, section_name):
        super(AwsSubAccountConfiguration, self).__init__()

        self.config = config
        self.enabled = self.config.getboolean(section_name, 'enabled', False)
        self.role_arn = self.config.get(section_name, 'role_arn', None)
        self.role_external_id = self.config.get(section_name, 'external_id', None)

class AwsSubAccount(object):
    """
    AWS sub-account
    """

    def __init__(self, parent, name):
        super(AwsSubAccount, self).__init__()

        self.parent_account = parent
        section_name = 'aws_sub_account_' + name
        self.sub_account_config = AwsSubAccountConfiguration(
            parent.config, section_name)

        self.instances = {}

    def get_account_id(self):
        """
        Gets the account id by either parsing it from the role ARN or by
        getting the currently logged in user's ARN and parsing from there.
        """

        return self.parent_account.get_account_id(
            self.sub_account_config.role_arn)

    def load_ec2_instance_data(self):
        """
        Loads all AWS EC2 instances and related tags in the account's regions
        Arguments:
        """

        for region in self.parent_account.regions:
            reg_config = (self.parent_account.config.get_region_config(region))
            ec2_tag_keys = reg_config.ec2_tag_keys
            self.instances[region] = AwsInstances(
                self, region, ec2_tag_keys, True)

    def get_instances(self, region):
        """
        Gets the instances for the given region
        Arguments:
        region - the region name
        Returns:
        AwsInstances object for the given region or None
        """

        if region in self.instances:
            return self.instances[region]
        else:
            return None

    def get_session(self, region, check_cache=True):
        """
        Creates a new session object in the given region
        Arguments:
        region - the region name
        check_cache - True to check the cache before creating new session
        """

        return self.parent_account.get_session(
            region, self.sub_account_config.role_arn,
            self.sub_account_config.role_external_id, check_cache)

#pylint: disable=too-few-public-methods
class AwsInstances(object):
    """
    Queries and caches the tags of all instances in a region.  Results are
    cached in a configured directory.  Cached results are used if the
    date of the file is within the last day (using modified time).
    The configuration object stores the AWS tag keys to retrieve from each
    instance.  If this configuration is not set (blank or null), this
    class does nothing.
    """
    def __init__(self, sub_account, region, ec2_tag_keys, load_now=False):
        """
        Initializes the class.
        Arguments:
        sub_account -
        region - the region name
        ec2_tag_keys - array of tag key names
        load_now -
        """

        super(AwsInstances, self).__init__()
        self.sub_account = sub_account
        self.region = region
        self.ec2_tag_keys = ec2_tag_keys
        self.instances = None
        if load_now:
            self.load()

    def _get_cache_file_path(self):
        """
        Generates a file path for the given account
        Arguments:
        sub_account - the account
        """
        fname = ('instance_tag_%s_cache_%s.json' %
                 (self.sub_account.get_account_id(), self.region, ))
        return os.path.join(CACHE_DIR, fname)

    def _query_instance_tags(self):
        """
        Calls EC2.DescribeInstances() and retrieves all instances and their tags
        """

        self.instances = {}

        _instances = (self.sub_account.get_session(self.region)
                      .resource('ec2').instances.all())
        for instance in _instances:
            tags = {}

            # hard-coded instance attributes (data coming from instance object)
            if 'instanceType' in self.ec2_tag_keys:
                tags['instanceType'] = instance.instance_type
            if 'imageId' in self.ec2_tag_keys:
                tags['imageId'] = instance.instance_type
            if 'publicDnsName' in self.ec2_tag_keys:
                tags['publicDnsName'] = instance.public_dns_name
            if 'privateDnsName' in self.ec2_tag_keys:
                tags['privateDnsName'] = instance.private_dns_name
            if 'vpcId' in self.ec2_tag_keys:
                tags['vpcId'] = instance.vpc_id
            if 'architecture' in self.ec2_tag_keys:
                tags['architecture'] = instance.architecture

            # tags coming from the EC2 tags
            if instance.tags:
                for tag in instance.tags:
                    if (self.ec2_tag_keys[0] == '*' or
                            tag['Key'] in self.ec2_tag_keys):
                        tags[tag['Key']] = tag['Value']

            # store the tags in the dictionary
            self.instances[instance.id] = tags

        # store the results on disk for next time
        with open(self._get_cache_file_path(), 'w') as cachefd:
            json.dump(self.instances, cachefd)

    def _load_instance_tags_from_cache(self):
        """
        Loads the tags from the cache file if it exists.
        Returns:
        True - when data loaded from cache; False - o/w
        """

        path = self._get_cache_file_path()
        if os.path.exists(path):
            now = datetime.datetime.utcnow()
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            time_to_refresh = mtime + datetime.timedelta(days=1)
            if now > time_to_refresh:
                with open(path, 'r') as contents:
                    self.instances = json.load(contents)
                    return True

        return False

    def load(self):
        """
        Loads the instances and their tags.  Caches that data for at most one
        day (configurable?).
        """

        if self.instances or not self.ec2_tag_keys:
            return
        if not self._load_instance_tags_from_cache():
            self._query_instance_tags()

    def __contains__(self, item):
        if not self.instances:
            return False
        return item in self.instances
    def __getitem__(self, item):
        if not self.instances:
            return None
        return self.instances[item]
