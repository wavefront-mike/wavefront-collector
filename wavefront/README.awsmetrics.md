### Overview
This command retrieves AWS CloudWatch metrics.  The metrics retrieved are configurable as are the stats for each metric.

### Command Line Options
| Option | Description | Default |
| ------ | ----------- | ------- |
| --config `FILE` | Full path to the configuration file | /opt/wavefront/etc/aws-metrics.conf |

### Configuration
The configuration is retrieved from and stored in an INI-formatted file with multiple groups.  Each group is described in more detail in the following sections.

This configuration file also acts as a fileconfig for the logger.  See [fileConfig definition](https://docs.python.org/2/library/logging.config.html#logging.config.fileConfig) for more details on how to configure logging.

#### Section: options
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| single_stat_has_suffix | If there is only a single stat (average, etc), then this configuration is checked to determine if the suffix for that stat (e.g., .average) or not.  When True, even if there is only one stat for a given metric, the suffix is added.  When False, if there is only one stat for a given metric, the suffix is NOT added | No | True |
| first_run_start_minutes | The number of minutes back to retrieve when running for the first time | No | 5 |
| metric_name_prefix | The prefix to add to all metrics | No | |
| ec2_tag_keys | Comma separated list of EC2 tag key names to add on to each point tag.  If set, DescribeInstances() is called and the tag keys set for this configuration are retrieved and added to any metric where the given instance is the source | No | |
| delay | The number of seconds to delay between each run | No | 300 |
| cache_dir | The directory where the instance cache list is stored.  DescribeInstances() response is cached for 1 day.  | No | /tmp |
| metric_config_path | The path to the metric configuration file.  (See metric configuration section above) | Yes | |
| number_of_threads | The number of threads to run in parallel for retrieving metrics | No | 10 |

#### Section: aws
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| access_key_id | The AWS access key ID | Yes | None |
| secret_access_key | The AWS secret access key | Yes | None |
| regions | Comma-separated list of regions to query | Yes | None |

#### Section: filter
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| start_time | The starting time (YYYY-MM-DDTHH:mm:ss+00:00) | No | None |
| end_time | The ending time (YYYY-MM-DDTHH:mm:ss+00:00) | No | None |

#### Section: writer
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| host | The host/IP of the writer endpoint | Yes | 127.0.0.1 |
| port | The port of the writer endpoint | Yes | 2878 |
| dry_run | Don't actually send data points to the writer endpoint configured.  Instead, print it on stdout. | No | True |

#### Section: assume_role
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| role_arn | THe AWS Role ARN to assume | No | |
| role_session_name | The AWS Session name when assuming a role | No | |
| role_external_id | The AWS external ID to use when assuming the above role | No | |

#### Section: billing
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| enabled | Should this script try to get the billing details CSV file | yes | False | 
| s3_region | The region where the csv files are being placed | no | None |
| s3_bucket | The bucket in the s3_region where the csv files are being placed | no | None |
| s3_path | The path in the s3_bucket where the csv files are being placed | no | None |

### Metrics Configuration
The metrics configuration file describes the metrics and their stats which should be retrieved from AWS CloudWatch.

This configuration file should contain a JSON dictionary stored at the top level of the configuration file object under the "metrics" key.

Each key in the "metrics" object is a regular expression and the value is an object with keys:
    * stats
        a list of statistics to pull down with the GetMetricStatistics() call.  Valid values are any of : 'Average', 'Maximum', 'Minimum', "SampleCount', 'Sum'
    * source_names (optional)
        an array of :
          - tag names (Dimensions)
          - Dimensions array index (0 based)
          - String literals
        The first match is returned as the source name.  If source_names is not present in the configuration, `DEFAULT_SOURCE_NAMES` array defined in the Python file is used.

 The key to the dictionary is a regular expression that should match a:
     `<namespace>.<metric_name>` (lower case with period escaped with a backslash)

An example of this is:
```
{
    "metrics": {
        "aws\\.lambda\\..*": {
            "stats": [
                "Average",
                "Minimum",
                "Maximum",
                "Sum"
            ],
            "priority": 0,
            "dimensions_as_tags": ["A", "B", "C"],
            "source_names": ["A"]
        },
        ...
    }
}

#### JSON configuration items
| Key Name | Type | Description |
| -------- | ---- | ----------- |
| "metrics" | Object | Top-level object.  Key must be "metrics" |
| _regular expression_ | Object | Object describing how to retrieve metrics for the matching expression.  The regular expression must be made up of NAMESPACE\\.... where NAMESPACE should have blackslashes replaced with ".".  For example, the regular expression for everything under AWS/EC2 namespace is `aws\\.ec2\\..*`.|
| "stats" | Array of Strings | Array of stat names to get for this metric.  Should be any of "Average", "Minimum", "Maximum", "SampleCount", "Sum" |
| "priority" | Number | If there are multiple matches for a given metric name when searching for a configuration, then the lowest priority will be used. |
| "dimensions_as_tags" | Array of Strings | List of dimension key names to use as point tags |
| "source_names" | Array of Strings | Array of string names to use as potential source values.  Each name is checked in order.  If a value is found (other than null or blank), it is selected as the source. See more details below in `Source Determination` section |

### Source Determination
The source attribute is determined by either the `source_names` field in the metric configuration file (see above section) or by the hard-coded list in the [awsmetrics.py](source file).  The metric configuration and the source `DEFAULT_SOURCE_NAMES` is an array that can contain any of the following:
- A key name from the dimensions of the CloudWatch metric or any other point tag
- A numeric value will resolves value of the Dimension at that index
- A string literal with an equals (=) sign as first character (e.g., "=LITERAL")

### Start and End Time
If the script has never been run, the default behavior is to get data from 5 minutes ago.  This can be controlled by the `first_run_start_minutes` configuration option.
For each subsequent run, the start time is equal to the `last_run_time` and the end time is the current run time.
After each run, the `last_run_time` is updated to the current run's `end time`.
