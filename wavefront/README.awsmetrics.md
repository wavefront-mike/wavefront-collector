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
            "priority": 0
        },
        ...
    }
}
```

### Source Determination
The source attribute is determined by either the `source_names` field in the metric configuration file (see above section) or by the hard-coded list in the [awsmetrics.py](source file).  The metric configuration and the source `DEFAULT_SOURCE_NAMES` is an array that can contain any of the following:
- A key name from the dimensions of the CloudWatch metric or any other point tag
- A numeric value will resolves value of the Dimension at that index

### Start and End Time
If the script has never been run, the default behavior is to get data from 5 minutes ago.  This can be controlled by the `first_run_start_minutes` configuration option.
For each subsequent run, the start time is equal to the `last_run_time` and the end time is the current run time.
After each run, the `last_run_time` is updated
