# SARIF v2.1.0 Python Module for CheckmarxOne

This is a Python 3.9+ module for generating SARIF logs for scans from CheckmarxOne.

It can be executed as a command line application or integrated into your own applications via the
module's API.  The generated SARIF log file is designed to align closer with the SARIF standard than
the SARIF logs output by the CheckmarxOne CLI.


## Features

* Generates one SARIF `Run` entry per scan engine.
  * SAST with API Security scan inventory items added to `Result` entries as applicable.
  * SCA
  * Container Security
* A command-line interface is available that can generate SARIF logs in files for one or more scan ids.
* The module API can be used to integrate SARIF log generation into your own applications.
* Can be used with CheckmarxOne single- or multi-tenant environments.


## Installing

The module can be installed manually the URL for the install `.whl` file from the Releases:

```
pip install https://github.com/checkmarx-ts/cxone-sarif/releases/download/1.0.3/cxone_sarif-X.X.X-py3-none-any.whl
```

## Using the API

The `__main__.py` file is a good example of using the `cxone_sarif` module.  The basics:

```Python
import cxone_api as cx
from cxone_sarif import get_sarif_v210_log_for_scan
from cxone_sarif.opts import DEFAULT

# Create an instance of the cxone-async-api client
client = cx.CxOneClient.create_with_XXXX(...)
sarif_log = await get_sarif_v210_log_for_scan(client, DEFAULT, "<scan id>")
```

## Using the Command Line

Execute the module to display the help:

```
python3 -m cxone_sarif -h
```
