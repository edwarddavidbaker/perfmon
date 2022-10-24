## Overview
The goal of this helper script is to automatically check perfmon's mapfile against CPU IDs mentioned
in the upstream Linux kernel.

## Setup
Install required packages either using the package manager or with `pip`.

```
pip install -r requirements.txt
```

Pass a proxy setting if necessary.
```
pip install --proxy <proxy> -r requirements.txt
```

## Running
```
python mapfile_kernel_comparison.py -p <path to local checkout of perfmon> -k <path to local checkout of upstream kernel>
```

### Running Tests

```
python -m unittest
```

## Formatting
VS Code was configured as below for formatting Python sections of this project.

```
"python.formatting.provider": "yapf",
"python.formatting.yapfArgs": [
    "--style={based_on_style: google, indent_width: 4, column_limit: 100}"
]
```