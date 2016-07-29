# Overview
The AWS Billing (awsbilling) command retrieves [AWS Reports](http://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/detailed-billing-reports.html) and generates metrics from any of the CSV-based reports.  This has been tested with:
- [AWS cost and usage report](http://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/detailed-billing-reports.html#enhanced-reports)
- [Detailed Billing Report with Resources and Tags](http://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/detailed-billing-reports.html#reportstagsresources)

The schema of the CSV files was once in the AWS documentation, but I can no longer find it.  It can be found [here](http://www.dowdandassociates.com/products/cloud-billing/documentation/1.0/schema/) instead.

# Processing Overview
This script processes each billing file defined in the configuration file.  Each file is processed in serial.

## Finding and Opening
The file is retrieved from an S3 bucket using the role provided.  The path in the S3 bucket is determined from the configuration.  The path should contain a reference to at least one variable `${date}` which will be replaced by 'YYYY-mm' (using the current date and time).  If no file is found with the configured prefix, the processing will stop.

There are two different file types supported: a `.csv` file or a `.csv.zip` file.  Once the first match is found, the file is opened (an optionally unzipped).

## Pre-Processing
The header row is parsed and the contents of each column is stored as the key in a dictionary that maps it to the column index.

If the `record_id_column_name` is set and there is a `last_record_id_<YYYY-MM>`, then each row is checked to see if record_id is greater than `last_record_id_<YYYY-MM>`.  Once the next record is found, processing begins.

## Processing
Once all the pre-processing is complete, each row is read line by line and the metric(s) are created.

Processing can pause and sleep after a certain number of rows has been processed if configured to do so.  In addition, a maximum number of rows can be set to stop processing after reached.

# Command Line Options
| Option | Description | Default |
| ------ | ----------- | ------- |
| --config `FILE` | Full path to the configuration file | /opt/wavefront/etc/aws-metrics.conf |

# Configuration
The configuration is retrieved from and stored in an INI-formatted file with multiple groups.  Each group is described in more detail in the following sections. 

This configuration file also acts as a fileconfig for the logger.  See [fileConfig definition](https://docs.python.org/2/library/logging.config.html#logging.config.fileConfig) for more details on how to configure logging.

A sample configuration is provided [here](https://github.com/wavefront-mike/wavefront-collector/tree/master/data/awsbilling-sample-configuration/awsbilling.conf).

## Section: aws_billing
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| enabled | Indicates if billing metrics are enabled | No | False |
| role_arn | The AWS Role ARN to assume to be able to access the files from S3 | No | |
| external_id | The AWS external ID | No | |
| billing_threads | Comma-separated list of thread names.  Each thread will have a corresponding section named `billing-<name>`. | No | Empty list |
| ec2_tag_keys | Comma separated list of EC2 tag key names to add on to each point tag.  If set, DescribeInstances() is called and the tag keys set for this configuration are retrieved and added to any metric where the given instance is the source | No | |

## Section: billing-<name>
Each billing thread listed in the `billing_threads` configuration in `aws_billing` section will have a corresponding section.

| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| enabled | Indicates if billing metrics are enabled | No | False |
| namespace | The top level category to put each metric in.  The trailing '.' is not needed (and will be appended automatically). | Yes | None |
| s3_region | The S3 region where the billing file is located | Yes | None |
| s3_bucket | The S3 bucket where the billing file is located | Yes | None |
| s3_prefix | The S3 prefix (i.e., path to the latest file).  The value can contain variables `${account_id}` and `${date}` | Yes | None |
| header_row_index | The index of the header row in the CSV file obtained from the above S3 path. Use -1 to indicate there is no header row.  (Header rows are ignored.)  This is a 1-based numeric value. | No | 1 |
| dimension_column_names | Comma-separated list of the names (in the header row) of the columns that will be point tags.  Each string can contain 1-2 components separated by a colon (':').  The first component, the name, is required.  The second component is the point tag name.  An example is 'Foo:Bar'.  'Foo' is the name defined in the column's header row and 'Bar' is the point tag name that will be used in the WF metric. | Yes | empty list |
| metric_column_names | Comma-separated list of column names (from header row) that will be metrics.  Each string can contain the same 1-2 components defined in `dimension_column_names` | Yes | empty list |
| date_column_names | Comma-separated list of column names (from header row) that are date-time values.  Each string must contain 2 components separated by a pipe (&#124;).  The first component is the column header name and the second component is the format that the value in the column is in | No | empty list |
| duration_column_names | Comma-separated list of column names to calculate a duration from.  This must contain 2 and only 2 values or it will be ignored.  The first value in the list (index 0) is the starting date column header name.  The second value in the list (index 1) is the ending date column header name.  Both values must contain 2 components separated by a pipe (&#124;). The first component is the column header name and the second component is the format that the value in the column is in.  If the duration calculated is greater than 0 seconds, a metric will be added with the name <metric name>.duration that is the duration in seconds of this row | No | empty list |
| instance_id_columns | Comma-separated list of column names (from header row) that contain instance ID | No | empty list |
| delay | Integer value indicating the number of seconds to wait between each run of this CSV file | No | 3600 |
| last_run_time | The date and time of the last run of this CSV file | No | None |
| record_id_column_name | The name of the column (from header row) that contains a "record ID".  This is used to avoid reprocessing rows that have already been processed. | No | None |
| maximum_number_of_rows | The maximum number of rows to process during each run. | No | 0 |
| sleep_after_rows | Sleep after processing this many rows | No | 0 |
| sleep_ms | If `sleep_after_rows` is set, then this value indicates how many milliseconds to sleep between each iteration.  | No | 0 |


## Section: writer
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| host | The host/IP of the writer endpoint | Yes | 127.0.0.1 |
| port | The port of the writer endpoint | Yes | 2878 |
| dry_run | Don't actually send data points to the writer endpoint configured.  Instead, print it on stdout. | No | True |

## Section: aws
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| access_key_id | The AWS access key to use when connecting to AWS  | Yes | None |
| secret_access_key | The AWS secret access | Yes | None |
| regions | Comma separated list of regions to connect to | Yes | None |
| sub_accounts | Comma separated list of sub-account names. Each name corresponds to a section in the config file | No | None |
