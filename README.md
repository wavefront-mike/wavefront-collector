## Overview
The `wavefront` script facilitates external integrations with Wavefront.  Each new integration is built as a subcommand of the `wavefront` command script.  `wavefront` provides a framework to quickly build new subcommands.  The framework supports several common features:

* daemonize
* PID file creation
* multiple command parallel processing
* continuous execution with delay between each run
* execute command(s) via command line or configuration file

## Existing Commands
| Command Name | Description | Python File |
| ------------ | ----------- | ----------- |
| [newrelic](docs/README.newrelic.md) | New Relic metrics imported into Wavefront.  Additionally, supports executing insight queries. | [newrelic.py](wavefront/newrelic.py) |
| [awscloudwatch](docs/README.awsmetrics.md) | AWS Cloudwatch metrics | [awsmetrics.py](wavefront/awsmetrics.py) |
| [awsbilling](docs/README.awsbilling.md) | AWS Billing metrics | [awsmetrics.py](wavefront/awsmetrics.py) |
| [systemchecker](docs/README.system_checker.md) | System Checker sends events to Wavefront when core dump files are found or when files have changed | [system_checker.py](wavefront/system_checker.py) |


## Running
The `wf` (or `wave.py`) script is the primary interface to this utility.  The `wf` script is used to run one or more of the subcommands at one time and to pass the configuration file to each.

It has 2 methods of operation:
1. [Command line](#cmdline)
2. [Configuration file](#configfile)

### <a name="cmdline">Command Line</a>
The command line operation allows you to run a single subcommand in either the foreground or background.
The `wf` script in command line mode has the following options:
| Argument | Option | Description |
| -------- | ------ | ----------- |
| --daemon | N/A    | Run in the background as a daemon. (Default is foreground without this option) |
| --pid    | FILE   | When running in daemon mode (--daemon), FILE represents the path to the PID file where the PID will be written (default: ./wavefront.pid) |
| --out    | FILE   | When running in deamon mode (--daemon), FILE represents the path to the STDOUT and STDERR (default: ./wavefront.out) |
| COMMAND | --config FILE | Execute the given command (see `Existing Commands` section above for names available).  The `--config FILE` argument allows you to provide the configuration file to the COMMAND. |


### <a name="configfile">Configuration File</a>
The configuration file operation mode allows you to run one or more subcommands.

The `wf` script in configuration file mode has the following options:
| Argument | Option | Description |
| -------- | ------ | ----------- |
| -c | FILE | The configuration file to describe the commands to execute.  This is the option that puts the script into "configuration file mode". See below for details on the configuration file. |
| --daemon | N/A    | Run in the background as a daemon. (Default is foreground without this option) |
| --pid    | FILE   | When running in daemon mode (--daemon), FILE represents the path to the PID file where the PID will be written (default: ./wavefront.pid) |
| --out    | FILE   | When running in deamon mode (--daemon), FILE represents the path to the STDOUT and STDERR (default: ./wavefront.out) |

#### Configuration File Specification
##### Section: global
| Configuration Key | Required? | Default | Description |
| ----------------- | --------- | ------- | ----------- |
| daemon | N | false | Run in the background or foreground.  The command line option will override this value. |
| out | N | ./wavefront.out | The file to put the STDOUT and STDERR in.  The command line option will override this value.  NOTE: This is only valid when in daemon mode |
| pid | N | ./wavefront.pid | The location of the PID file.  The command line option will override this value.  NOTE: This is only valid when in daemon mode |
| threads | Y | None | The comma-separated list of commands to run in separate threads.  The name provided here can be anything as it is just a placeholder for the section name where the configuration of each command resides |

##### Section: thread-[thread name]
There should be one section per name listed in the `threads` key in the `global` section.
| Configuration Key | Required? | Default | Description |
| ----------------- | --------- | ------- | ----------- |
| command | Y | None | The name of the command to execute |
| args | Y | None | The comma separated list of arguments.  Each argument should be separated by a comma (even values provided to a given argument).  Example: --config,foo.conf,--verbose |
| delay | N | None | The number of seconds to delay between each iteration of this command being executed.  If delay is not set, only one iteration will be executed and the `wf` script will end. |

## service script
`wavefront-collector` is provided to execute the collector as a service.

## Examples
### Execute the `systemchecker` command in the foreground one iteration
```
> wf systemchecker --config system_checker.conf
```

system_checker.conf
```
[global]
cache_dir=/tmp/sc-wavefront-cache

[cores]
paths=/tmp/
patterns=core*

[wavefront]
api_key=TOKEN
api_base=https://INSTANCE.wavefront.com
```

### Execute `systemchecker` and `awscloudwatch` in the foreground via the command line mode (iterating once every 60 and 90 seconds respectfully)
```
> wf -c example.conf
```

example.conf:
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


