# Overview
This file contains steps necessary to add a new command to the Wavefront Collector.

# Steps
## Step 1: Create Python File
Create a new class for your command in a new file.  The file name should be `[COMMAND NAME].py` and saved in the `wavefront` subdirectory.

The class should derive from `command.Command` and implement the following functions:

| Function/Property | Required | Description |
| -------- | -------- | ----------- |
| description | Yes | Short description of this command.  This is displayed in the log output.  Set in `__init__()` |
| _initialize() | Yes | Initializes the command object (run once when the command is run and never again - i.e., not every execute cycle) |
| _execute() | Yes | Implement the command's processing logic here.  This function is called for each execution. |
| get_help_text() | Yes | Returns the text to display when showing help text for this command |

## Step 2: Update wave.py to include new command
Update `wave.py` `INSTALLED_COMMANDS` dictionary to include the new comand.  The dictionary key is the command's name (the name that will be used to run it) and the value is a tuple : `('wavefront.[COMMAND NAME]', '[MAIN COMMAND CLASS NAME]'_`.

## Step 3: Add a README and update main README.md
Create a new `README.[COMMAND NAME].md` in the `docs` directory describing this command.  Update `README.md` in the root directory to include a reference to the new command.

## Step 4: Add sample configuration files
Add any sample configuration files to the `data/[COMMAND NAME]-sample-configuration` directory.

## Step 5: Test
Test out your new command.

## Step 6: Update GitHub and PyPi
Once the new command is working as expected, push the update to GitHub and create a new pull request on the public wavefrontHQ repository.
Increment `setup.py` `version` and then push to PyPi repo.  See [README.setup_py.md](README.setup_py.md) for more details.
