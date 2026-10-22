[![Tests](https://github.com/malakellamti/configguard/actions/workflows/tests.yml/badge.svg)](https://github.com/malakellamti/configguard/actions/workflows/tests.yml)

# ConfigGuard

ConfigGuard is a lightweight, command-line security tool written in Python that scans configuration files and directories for potential hardcoded secrets.

It is designed as a small security-auditing project to explore secret detection, regular expressions, filesystem safety, automated testing, and machine-readable output.

## Features

- Detects potential API keys and secrets using configurable naming patterns.
- Identifies AWS access key IDs.
- Detects database connection strings containing credentials.
- Detects private-key headers.
- Recognizes GitHub-style personal access tokens.
- Reports the file and line number for each finding.
- Supports human-readable and JSON output.
- Scans directories recursively.
- Skips symbolic links and non-regular files during directory scans.
- Includes automated tests for detection rules, false positives, and error handling.

## Requirements

- Python 3.10 or later
- No third-party runtime dependencies

## Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/malakellamti/configguard.git
cd configguard
```

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install the project in editable mode:

```bash
python -m pip install -e .
```


## Usage

Scan a single file:

```bash
configguard path/to/settings.env
```

Scan a directory recursively:

```bash
configguard path/to/configuration/
```

Output results as JSON:

```bash
configguard path/to/settings.env --json
```

Display available options:

```bash
configguard --help
```

## Example

Given a configuration file containing test data such as:

```dotenv
API_KEY=example-fake-key
DATABASE_URL=postgres://user:password@localhost/example
```

ConfigGuard reports potential findings with their file paths, line numbers, and rule identifiers.

The scanner does not print the matched secret value in its finding message.

## Exit Codes

| Exit code | Meaning |
|---|---|
| `0` | Scan completed without findings or errors |
| `1` | Potential secrets were found |
| `2` | Invalid target or scan errors occurred |

## Testing

Run the automated test suite from the project root:

```bash
python -m unittest discover -s tests -v
```

The tests cover detection rules, safe configuration examples, environment-variable references, comments, line numbers, missing files, symbolic links, and JSON CLI behavior.

## Limitations

ConfigGuard uses regular expressions and heuristic rules. It cannot guarantee that every secret will be detected, and some matches may be false positives.

- Detection depends on the patterns implemented by the scanner.
- A finding indicates a potential secret, not confirmed credential validity.
- The current implementation focuses on text-based patterns rather than provider-specific validation.
- Always review findings manually.
- Never use real credentials in test fixtures or commit secrets to version control.

For production use, consider combining this tool with dedicated secret-scanning tools and secret-management practices.

## Project Status

ConfigGuard is an educational security project under active development.

## License

MIT
