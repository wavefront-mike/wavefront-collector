## Overview
The Wavefront collector facilitates external integrations with Wavefront. This allows metrics from external services such as New Relic to be pulled into Wavefront. Each integration is a executed via this utility using the command name specified in the table below.

## Current Integrations
| Integration | Command Name | Description | Python File |
| --- | --- | --- | --- |
| New Relic | [newrelic](https://github.com/wavefront-mike/wavefront-integrations-tool/blob/master/docs/README.newrelic.md) | Extracts metrics from New Relic API | [newrelic.py](https://github.com/wavefront-mike/wavefront-integrations-tool/blob/master/wavefront/newrelic.py) |
| AWS Cloudwatch | [awscloudwatch](https://github.com/wavefront-mike/wavefront-integrations-tool/blob/master/docs/README.awscloudwatch.md) | Metrics pulled from AWS Cloudwatch | [awscloudwatch.py](https://github.com/wavefront-mike/wavefront-integrations-tool/blob/master/wavefront/awscloudwatch.py) |
| AWS Billing | [awsbilling](https://github.com/wavefront-mike/wavefront-integrations-tool/blob/master/docs/README.awsbilling.md) | AWS Billing metrics retrieved from Billing Reports | [awsbilling.py](https://github.com/wavefront-mike/wavefront-integrations-tool/blob/master/wavefront/awsbilling.py) |
| Linux System Checker | [systemchecker](https://github.com/wavefront-mike/wavefront-integrations-tool/blob/master/docs/README.system_checker.md) | Creates Wavefront events when files matching a pattern are found (e.g., core dumps) or when files have changed | [system_checker.py](https://github.com/wavefront-mike/wavefront-integrations-tool/blob/master/wavefront/system_checker.py) |

## Installation
Install using pip or using the provided setup.py.

```
> pip install wavefront_collector
```

## Executing an Integration
The `wf` script (a symlink to `wave.py`) is the primary interface to running commands.  This script supports 2 methods of running a command:

1. [Command line](#cmdline)
2. [Configuration file](#configfile)


## <a name="cmdline">Run Method 1: Command Line</a>
Running a command via the command line is the simplest method.  It allows you to execute a single integration in either the foreground or background.  In this mode, the `wf` script has the following command line options:

| Argument | Option       | Description |
| -------- | ------------ | ----------- |
| `--daemon` | N/A    | Run in the background as a daemon. The default is foreground without this option. |
| `COMMAND` | N/A | Execute the given command (see `Current Integrations` section above for names available). |
| `--config` | `FILE` | Provide the configuration file to the `COMMAND`.  The default path and file is set by each command. |

Additional options available in daemon mode (i.e., when using --daemon option):

| Argument | Option       | Description |
| -------- | ------------ | ----------- |
| `--pid`    | `FILE`   | The path to the PID file where the PID will be written (default: ./wavefront.pid) |
| `--out`    | `FILE`   | The path to the file that will capture STDOUT and STDERR (default: ./wavefront.out) |
| `--delay` | `SECONDS` | The number of sections to delay between each iteration (default: 90) |

### Command Line Examples
Examples of executing the `systemchecker` integration from the command line using the `system_checker.conf` file.

**`system_checker.conf`**
```
[global]
cache_dir=/tmp/sc-wavefront-cache

[find_files]
paths=/tmp/
patterns=core*
event_names=core-dump

[wavefront]
api_key=TOKEN
api_base=https://INSTANCE.wavefront.com
```

**Execute the `systemchecker` command just once in the foreground**
```
> wf systemchecker --config system_checker.conf
```

**Execute the `systemchecker` command in the background and continue running every 30s**
```
> wf --daemon --delay 30 systemchecker --config system_checker.conf
```

## <a name="configfile">Run Method 2: Configuration File</a>
The configuration file execution mode allows you to run one or more commands (either simultaneously or separately).  In this mode, the `wf` script has the same command line options as the [command line mode](#cmdline).  Options specified on the command line take precedence over those in the configuration file.  One additional required argument is the configuration file path:

| Argument | Option | Description |
| -------- | ------ | ----------- |
| `-c` | `FILE` | The configuration file to describe the command(s) to execute.  This is the option that puts the script into "configuration file mode". See below for the supported options in the configuration file. |

`-c FILE` option *must* be supplied on the command line to indicate to `wf` that it should determine which command(s) to run from the configuration file `FILE`.

### Configuration File Specification
This section outlines the specification of the configuration file that the `wf` script supports when loading and executing commands from a file rather than the command line.

#### Section: global
| Configuration Key | Required? | Default        | Description |
| ----------------- | --------- | -------------- | ----------- |
| daemon | N | false | Run in the background or foreground.  The command line option will override this value. |
| out | N | ./wavefront.out | The file to put the STDOUT and STDERR in.  The command line option will override this value.  NOTE: This is only valid when in daemon mode |
| pid | N | ./wavefront.pid | The location of the PID file.  The command line option will override this value.  NOTE: This is only valid when in daemon mode |
| threads | Y | None | The comma-separated list of commands to run in separate threads.  The name provided here can be anything as it is just a placeholder for the section name where the configuration of each command resides.  Each name listed here requires an additional section in the configuration file labeled `thread-[thread name]`. |

#### Section: thread-[thread name]
There should be one section per name listed in the `threads` key in the `global` section.

| Configuration Key | Required? | Default | Description |
| ----------------- | --------- | ------- | ----------- |
| command | Y | None | The name of the command to execute |
| args | Y | None | The comma separated list of arguments.  Each argument should be separated by a comma (even values provided to a given argument).  Example: --config,foo.conf,--verbose |
| delay | N | None | The number of seconds to delay between each iteration of this command being executed.  If delay is not set, only one iteration will be executed and the `wf` script will end. |

## Service Script
`wavefront-collector` is provided to execute the collector as a service.  This script has following options:

`start`   -  starts the service running in the background using `--daemon` `--pid /tmp/wavefront-collector.pid` `--out /tmp/wavefront-collector.log` `-c /opt/wavefront/etc/wavefront-collector.conf`

`stop`    -  stops the service by sending a SIGTERM signal to the PID in the PID file `/tmp/wavefront-collector.pid`

`status`  -  prints the current status of the service (running or not) and the last lines of the log file if the service is running

`restart` -  stops, then starts the service using the above commands

### Configuration File Examples
**Execute `systemchecker` and `awscloudwatch` in the foreground via the command line mode (iterating once every 60 and 90 seconds respectfully)**
```
> wf -c example.conf
```

**`example.conf`**
```
[global]
pid=/tmp/wf.pid
out=/tmp/wf.out
daemon=false
threads=sc1,cloud1

[thread-sc1]
command=systemchecker
args=--config,system_checker.conf
delay=60

[thread-cloud1]
command=awscloudwatch
args=--config,awscloudwatch.conf
delay=90
```


