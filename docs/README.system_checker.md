### Overview
This command handles system-related checks such as looking for core dumps or checking for changes in files (using MD5 checksum).

### Checkers
#### Core Dump Checker
This checker looks for core dumps in a configurable set of directories.  If the file exists, it will send an event to Wavefront and record the core in the cache location so it won't be sent again.

#### File changed Checker
This checker is used to compare MD5 checksums of a set of files.  If the MD5 checksum has changed, an event is sent to Wavefront.  Once the event is recorded, the MD5 checksum is updated.  Only one event is sent for each file change.

### Command Line Options
| Option | Description | Default |
| ------ | ----------- | ------- |
| --config `FILE` | Full path to the configuration file | /opt/wavefront/etc/system_checker.conf |

### Configuration
The configuration is retrieved from and stored in an INI-formatted file with multiple groups.  Each group is described in more detail in the following sections. 

This configuration file also acts as a fileconfig for the logger.  See [fileConfig definition](https://docs.python.org/2/library/logging.config.html#logging.config.fileConfig) for more details on how to configure logging.

#### Section: global
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| cache_dir | The directory where additional information is cached for each of the checkers.  For example, the core checker stores the MD5 of each core dump already handled | Yes | /tmp |
| source_name | The source name to send for this event | Yes | hostname |
| log_requests | Enable debug logging of API requests.  This is useful for debugging of APIs | No | False |
| ignore_ssl_cert_errors | True ignores the SSL errors/warnings when connecting to the API endpoint | False |

#### Section: wavefront
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| api_key | The API token to make API requests on behalf of | Yes | None |
| api_base | The API base URL | Yes | https://metrics.wavefront.com |

#### Section: cores
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| paths | Comma-separated list of paths to search for cores | No | None |
| patterns | Comma-separated list of patterns to search for in the directories in the `paths` key.  The number of values in this key must be the same as that of `paths`. | No | None |

#### Section: md5
| Option | Description | Required? | Default |
| ------ | ----------- | ------- | ------- |
| files | Comma-separted list of files including path that should be checked | No | None |
| expected_hashes | Comma-separated list of MD5 hashes that match the file in `files`.  If blank, the current MD5 of the file in `files` is calculated and used | None |


