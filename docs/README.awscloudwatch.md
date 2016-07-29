# Overview
The AWS Cloudwatch command (awscloudwatch) retrieves AWS CloudWatch metrics.  The metrics retrieved are configurable as are the stats for each metric.

# Processing Overview
Each region specified in the `regions` configuration option is executed in its own thread in parallel.  The metrics configuration file is scanned to find all namespaces that should be retrieved from the [ListMetrics()](http://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_ListMetrics.html) API.  Once a list of metrics is returned, a set of threads (the number defined by the `workers` configuration value) begin processing all the metrics.  Each worker calls [GetMetricStatistics()](http://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricStatistics.html) on the Namespace/MetricName requesting at most an entire day's worth of data.  If the script has not run in more than a day, this API is called multiple times.  Each metric and its corresponding value returned from the GetMetricStatistics() API is sent to the proxy.

# Command Line Options
| Option | Description | Default |
| ------ | ----------- | ------- |
| --config `FILE` | Full path to the configuration file | /opt/wavefront/etc/aws-metrics.conf |

# Configuration
The configuration is retrieved from and stored in an INI-formatted file with multiple groups.  Each group is described in more detail in the following sections. 

This configuration file also acts as a fileconfig for the logger.  See [fileConfig definition](https://docs.python.org/2/library/logging.config.html#logging.config.fileConfig) for more details on how to configure logging.

A sample configuration is provided [here](https://github.com/wavefront-mike/wavefront-collector/tree/master/data/awscloudwatch-sample-configuration/awscloudwatch.conf).

## Section: cloudwatch
For each of the items in this section, the default value comes from the `cloudwatch` section.  The value can be overridden in a region-specific section named `cloudwatch_<region name>`.  Any (or all) values can be overridden in the region-specific section.  Order or presidence is: region-specific -> `cloudwatch` section -> (code default value).

| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| enabled | Boolean value to indicate if the cloudwatch configuration is enabled | No | False |
| workers | The number of threads to run as workers for this cloudwatch configuration | No | 1 |
| single_stat_has_suffix | If there is only a single stat (average, etc), then this configuration is checked to determine if the suffix for that stat (e.g., .average) or not.  When True, even if there is only one stat for a given metric, the suffix is added.  When False, if there is only one stat for a given metric, the suffix is NOT added | No | True |
| first_run_start_minutes | The number of minutes back to retrieve when running for the first time | No | 5 |
| metric_name_prefix | The prefix to add to all metrics | No | |
| namespace | The top level namespace for metrics created.  The last "." is not needed. | No | "aws" |
| ec2_tag_keys | Comma separated list of EC2 tag key names to add on to each point tag.  If set, DescribeInstances() is called and the tag keys set for this configuration are retrieved and added to any metric where the given instance is the source | No | |
| metric_config_path | The path to the metric configuration file.  (See `Metrics Configuration` section for more details) | Yes | |
| start_time | The starting time (YYYY-MM-DDTHH:mm:ss+00:00) | No | None |
| end_time | The ending time (YYYY-MM-DDTHH:mm:ss+00:00) | No | None |
| last_run_time | The last run time of this configuration (YYYY-MM-DDTHH:mm:ss+00:00) | No | None |

## Section: writer
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| host | The host/IP of the writer endpoint | Yes | 127.0.0.1 |
| port | The port of the writer endpoint | Yes | 2878 |
| dry_run | Don't actually send data points to the writer endpoint configured.  Instead, print it on stdout. | No | True |

## Section: options
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| delay | The number of seconds to delay between each run | No | 300 |

## Section: aws
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| access_key_id | The AWS access key to use when connecting to AWS | Yes | None |
| secret_access_key | The AWS secret access | Yes | None |
| regions | Comma separated list of regions to connect to | Yes | None |
| sub_accounts | Comma separated list of sub-account names. Each name corresponds to a section in the config file | No | None |

## Section: <sub_account_name>
Each sub-account listed in the `sub_accounts` list should have a corresponding section.

| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| enabled | Is this sub account enabled? | No | False |
| role_arn | THe AWS Role ARN to assume | No | |
| external_id | The AWS external ID to use when assuming the above role | No | |
| access_key_id | The AWS access key to use when connecting to this sub account | Yes | None |
| secret_access_key | The AWS secret access | Yes | None |

# Metrics Configuration
The metrics configuration file describes the metrics and their stats which should be retrieved from AWS CloudWatch.

This configuration file should contain a JSON dictionary stored at the top level of the configuration file object under the "metrics" key.

The default configuration is provided [here](https://github.com/wavefront-mike/wavefront-collector/tree/master/data/awscloudwatch-sample-configuration/aws.json.conf).

Each key in the "metrics" object is a regular expression and the value is an object with the following keys:
   * stats
        a list of statistics to pull down with the GetMetricStatistics() call.  Valid values are any of : 'Average', 'Maximum', 'Minimum', "SampleCount', 'Sum'
   * source_names
        an array of :
          - Point tag name
          - Dimension name
          - String literal (must begin with an '=')
        The first name that contains a value is returned as the source name.
   * dimensions_as_tags
        Comma-separated list of dimension names to copy over as point tags
   * namespace
        The AWS namespace (AWS/EC2, etc.)
   * priority
        A numeric value indicating the priority of this configuration.  This is only used if more than one configuration matches the metric name.
 The key to the dictionary is a regular expression that should match a:
     `<namespace>.<metric_name>` (lower case with period escaped with a backslash)

An example of this configuration file is:
```
{
    "metrics": {
        "aws\\.rds\\..*": {
            "stats": [
                "Average",
                "Minimum",
                "Maximum",
                "Sum"
            ],
            "priority": 0,
            "dimensions_as_tags": ["DBInstanceIdentifier", "DatabaseClass", "EngineName"],
            "source_names": ["DBInstanceIdentifier", "=AWS"]
        },
        ...
    }
}
```

# Start and End Time
If the script has never been run, the default behavior is to get data from 5 minutes ago.  This can be controlled by the `first_run_start_minutes` configuration option.
For each subsequent run, the start time is equal to the `last_run_time` and the end time is the current run time.
After each run, the `last_run_time` is updated to the current run's `end time`.


