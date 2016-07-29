## Overview
The `appdynamics` command supports pulling metrics from AppDynamics.  It uses the [AppDynamicsREST](https://github.com/tradel/AppDynamicsREST/) client to interact with AppDynamics.

## Usage
1. Install the Wavefront Collector
2. Copy `appdynamics.conf` from `appdynamics-sample-configuration` to a directory of your choosing
3. Open `appdynamics.conf` in an editor and update the `api`, `filter`, and `writer` sections.  (See below for details)
4. Run the Wavefront Collector:
```wf -c wavefront-collector.conf```

## AppDynamics REST API and SDK
* [AppDynamics REST API Documentation](https://docs.appdynamics.com/display/PRO41/Use+the+AppDynamics+REST+API)
* [AppDynamicsREST Python SDK](https://github.com/tradel/AppDynamicsREST/) 
** [AppDynamicsREST Python SDK Documentation](http://appdynamicsrest.readthedocs.io/en/latest/appsphere.html)
** [AppDynamicsREST Python SDK Model Source](http://appdynamicsrest.readthedocs.io/en/latest/_modules/appd/model.html)

## Command Line Options
| Option | Description | Default |
| ------ | ----------- | ------- |
| --config `FILE` | Full path to the configuration file | /opt/wavefront/etc/newrelic.conf |

## Configuration
The configuration is retrieved from and stored in an INI-formatted file with multiple groups.  Each group is described in more detail in the following sections. 

This configuration file also acts as a fileconfig for the logger.  See [fileConfig definition](https://docs.python.org/2/library/logging.config.html#logging.config.fileConfig) for more details on how to configure logging.

### Section: api
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| account | The Account name on your AppDynamics account.  You can get this from the `/controller/#/location=SETTINGS_LICENSE` page on your controller. | Yes | None |
| username | The username to login as to create metrics.  Users can be created on the `/controller/#/location=SETTINGS_ADMIN` page. | Yes | None |
| password | The password associated with the username | Yes | None |
| controller_url | The Controller URL | Yes | None |
| debug | Verbose logging from the SDK ? | No | False |

### Section: filter
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| whitelist_regex | Comma-separated list of regular expressions to include.  This should match the form A|B|C ....  An example is : `blacklist_regex = Business Transaction Performance\|.*`| No | None |
| blacklist_regex | Comma-separated list of regular expressions to not include. White list trumps black list. | No | None |
| application_ids | Comma-separated list of AppDynamics application IDs to retrieve metrics from | No | All |
| start_time | Start time for range based backfilling query (YYYY-MM-DDTHH:mm:ss+00:00) | No | None |
| end_time | End time for range based backfilling query (YYYY-MM-DDTHH:mm:ss+00:00) | No | None |

### Section: writer
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| host | The host/IP of the writer endpoint | Yes | 127.0.0.1 |
| port | The port of the writer endpoint | Yes | 2878 |
| dry_run | Don't actually send data points to the writer endpoint configured.  Instead, print it on stdout. | No | True |

