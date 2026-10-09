# EVTX Triage Toolkit

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
