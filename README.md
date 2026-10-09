# EVTX Triage Toolkit (EvtxHound)

[![PyPI version](https://img.shields.io/pypi/v/evtx-hound.svg?color=blue)](https://pypi.org/project/evtx-hound/)
[![Python CI](https://github.com/ZlightkunZ/evtx-hound/actions/workflows/python-ci.yml/badge.svg)](https://github.com/ZlightkunZ/evtx-hound/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://static.pepy.tech/badge/evtx-hound)](https://pepy.tech/project/evtx-hound)

A high-performance Python CLI utility designed for incident responders and SOC analysts to quickly parse Windows Event Logs (`.evtx`) and identify suspicious parent-child process relationships.

## Features
- Parses `Security.evtx` and `Sysmon.evtx` locally.
- Identifies LOLBin (Living Off The Land Binaries) anomalies (e.g. `word.exe` spawning `cmd.exe`).
- Outputs findings to console, JSON, or CSV.

## Usage

```bash
pip install -r requirements.txt
python triage.py --file Security.evtx --output results.json
```
