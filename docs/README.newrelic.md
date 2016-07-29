### Overview
The `newrelic` command supports pulling metrics from New Relic at least every minute.  Application summary data can be polled every 30s, but is not guaranteed to be updated that often.

#### Usage
1. Install the Wavefront Collector
2. Copy the `newrelic-sample-configuration` files to same directory.
3. Open `newrelic-summary.conf` and `newrelic-details.conf` and set the `api.key` and `filter.application_ids` configuration items.  When complete, save wavefront.conf
4. Run the Wavefront Collector:
 ```wf -c wavefront-collector.conf```

#### New Relic API
* [API Documentation](https://docs.newrelic.com/docs/apis/rest-api-v2)
* [API Explorer](https://rpm.newrelic.com/api/explore)

### Command Execution flow
1. Determine start and end times.  
	1. If `start_time` is set in the configuration, then use that.  Otherwise, use the `last_run_time` value (set in the configuration to the last run's end time).  If neither `start_time` nor `last_run_time` is set, then use one minute prior to now.
	2. If `end_time` is set in the configuration, then use that.  Otherwise use now.
2. Get the Application metrics.
	1. Start from `/application.json` (filter with `filter[ids]` query string for all `application_ids` set in the configuration)
	1. Top level application summary metrics are obtained from the response if `include_application_summary` is enabled.  Data comes from `response['application_summary']`.
	1. Get the list of metrics to retrieve by querying `/applications/{application_id}/metrics.json`.
	   * Use the configuration items in the `filter` section to aid in this process.
	2. Application details are obtained if `include_hosts` is enabled.  Details for each host come from the REST API `/applications/{app_id}/hosts/{host_id}/metrics/data.json`. Each host is found in the `response['links']['application_hosts']` of the `/applications.json` response.
		* Each host returns application summary metrics as well.  And these metrics are obtained if `include_application_summary` is enabled.
3. Get the Server metrics.
	1. Start from `/servers.json` to get a list of all servers
	1. Top level server summary metrics are obtained from the `response['summary']` if `include_server_summary` is enabled. 
	2. Get the list of metrics to retrieve by querying `/servers/{server_id}/metrics.json`.
	2. Server details are obtained from `/servers/{server_id}/metrics/data.json` if `include_servers` is enabled.
		* Each server returns summary metrics as well.  And these metrics are obtained if `include_server_summary` is enabled.
4. Save the `last_run_time` in the configuration file to the end_time of this run.

### Command Line Options
| Option | Description | Default |
| ------ | ----------- | ------- |
| --config `FILE` | Full path to the configuration file | /opt/wavefront/etc/newrelic.conf |

### Configuration
The configuration is retrieved from and stored in an INI-formatted file with multiple groups.  Each group is described in more detail in the following sections. 

This configuration file also acts as a fileconfig for the logger.  See [fileConfig definition](https://docs.python.org/2/library/logging.config.html#logging.config.fileConfig) for more details on how to configure logging.

#### Section: api
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| key | New Relic API key.  Can be obtained from [here](https://rpm.newrelic.com/apikeys) | Yes | None |
| endpoint | New Relic API Endpoint | No | https://api.newrelic.com/v2 |
| log_path | Path to the log file that will store API requests | No | None |

#### Section: filter
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| names | Comma-separated list of specific names to retrieve | No | None |
| regex | Comma-separated list of regular expressions to match against results of the metrics.json calls.  White list.  Matches are retrieved from data.json. | No | None |
| blacklist_regex | Comma-separated list of regular expressions to not include. Black list trumps white list. | No | None |
| additional_fields | Comma-separated list of metric names to retrieve in addition to the ones returned by metrics.json calls.  By default, you probably will want to include `HttpDispatcher,Errors,Memcached,External` | No | None |
| application_ids | Comma-separated list of New Relic application IDs to retrieve metrics from | No | All |
| start_time | Start time for range based backfilling query (YYYY-MM-DDTHH:mm:ss+00:00) | No | None |
| end_time | End time for range based backfilling query (YYYY-MM-DDTHH:mm:ss+00:00) | No | None |

#### Section: options
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| include_application_summary | Include the summary metrics from the application API (error_rate, etc) | No | True |
| include_host_application_summary | Include the summary metrics from the /host/application API | No | True |
| include_hosts | Include the host metrics from /host/data.json | No | True |
| include_server_summary | Include the summary details from the /servers/data.json API | No | True |
| include_server_details | Include the server metrics from the /servers/data.json API | No | False |
| min_delay | The minimum number of seconds between the last run time and the current run time | No | 60 |
| skip_null_values | Do not include metrics with null values (0 is not null in this case) | No | False |
| default_null_value | If including null values, then replace 'null' with this value | No | 0 |
| max_metric_names | Maximum number of metric names to request at one time when querying `/data.json` API | No | 25 |
| workers | The number of threads to run when making `/data.json` requests | No | 30 |
| send_zero_every | Send 0 values no more than every x seconds. Set to 0 to send 0 values on every iteration. | No | 0 |

#### Section: wavefront_api
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| key | Wavefront API Key | No | None |
| endpoint | Wavefront endpont | No | https://metrics.wavefront.com/ |

#### Section: writer
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| host | The host/IP of the writer endpoint | Yes | 127.0.0.1 |
| port | The port of the writer endpoint | Yes | 2878 |
| dry_run | Don't actually send data points to the writer endpoint configured.  Instead, print it on stdout. | No | True |

#### Section: query_api
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| key | The New Relic Insights API Key | No | None |
| endpoint | The New Relic Insights API endpoint | https://insights-api.newrelic.com/v1 |

#### Section: queryXXX
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| enabled | Is this query enabled? | Yes | True |
| name | The name of this query | No | 'query' |
| query | The Insights query | Yes | None |

### Caching
The response from the `*/metrics.json` API calls is cached for a day in `/tmp/wfnrcache`.  One file is stored here per path.  The filename is the MD5 of the path.

### Standard Configuration
* [wavefront.conf](newrelic-sample-configuration/wavefront.conf)
	* Runs the script as a daemon with the PID file stored in the CWD (./wavefront.pid) and the stdout/stderr in ./wavefront.out.
	* Runs 2 threads: one for processing the summary and one for the details.
* [summary.conf](newrelic-sample-configuration/summary.conf)
	* gets the application summary every 30s (no details are retrieved so the summary metrics can be updated more frequently)
* [details.conf](newrelic-sample-configuration/details.conf)
	* gets the application (host) details and delays 5m between each run.
		
### New Relic Lessons Learned
* There is a limit to the number of metric names you can pass to the `/data.json` API.  The `max_metric_names` configuration item adjusts this number.   The code loops until all metrics have been retrieved.
* API keys are only available for owner or administrator role types.
* Retrieving metrics
	* If you attempt to retrieve metrics for a time range greater than 10 minutes, the granularity is adjusted in spite of the value of `period`
	* Multiple calls to `/data.json` can happen in parallel
	* Watch out for 'connection reset by peer' errors (New Relic closes connection in middle) and retry.
* There are several metric names that are not returned from `/metrics.json`.  The ones we found include:
	* HttpDispatcher
	* Errors
	* Memcached
	* External


