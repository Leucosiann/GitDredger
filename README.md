
**GitDredger** is a GitHub Archive scanner that detects exposed sensitive tokens, API keys, and credentials in real-time.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **Real-time scanning** of GitHub Archive data
- **Configurable patterns** via JSON
- **Parallel processing** for performance
- **Dual output formats** (detailed + tokens-only)

## Installation

```bash
git clone https://github.com/fatih-celik/GitDredger.git
cd GitDredger
pip install -r requirements.txt
```

## Quick Start

```bash
# Scan last 1 hour
python3 gitdredger.py -l 1

# Scan specific time range
python3 gitdredger.py -s "2024-01-01 12:00" -e "2024-01-01 15:00"

# Custom output and workers
python3 gitdredger.py -l 6 -o results.json -w 5
```

## Configuration

Patterns are loaded from `Config/Token_Regex.json` (git ignored for security):

```bash
# Use default patterns
python3 gitdredger.py -l 1

# Use custom patterns
python3 gitdredger.py -l 1 --config custom_patterns.json
```

## Output

Results are saved in `Outputs/` directory:
- **Detailed report**: Complete scan metadata with context
- **Tokens only**: Clean list for integration

## Command Options

| Option | Description |
|--------|-------------|
| `-l, --last-hours` | Scan last N hours |
| `-s, --start-time` | Start time (YYYY-MM-DD HH:MM) |
| `-e, --end-time` | End time |
| `-o, --output` | Output filename |
| `-w, --workers` | Parallel workers (default: 3) |
| `--no-save` | Don't save to file |
| `--config` | Custom config file |

## Example Output

```
📈 Total detections: 1,825
🔍 Detected pattern types: 3

🚨 Detected Patterns:
   grafana_cloud_api_token: 1,864 instances
   pypi_upload_token: 27 instances
   github_token: 1 instances
```

## Security Notice

- **Educational purpose only**
- Scans public GitHub data only
- Report vulnerabilities responsibly
- Comply with GitHub Terms of Service

## License

MIT License - see [LICENSE](LICENSE) file. 
