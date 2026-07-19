# wp2Shell Scanner – with PoC

> CVE-2026-63030 and CVE-2026-60137 – WordPress wp2shell vulnerability-chain scanner
> 
> Authorized security-research tool with optional command-verification PoC.

`wp2shell-scanner` detects the WordPress wp2shell vulnerability chain by
validating public WordPress evidence, fingerprinting exposed versions, checking
REST batch behavior, and measuring an active timing differential. It is
intended for authorized defensive research, CTF environments, and systems you
own or administer.

* * *

## ⚠️ Legal & ethical disclaimer

This project is provided strictly for authorized security testing and defensive
research.

- Use it only against systems you own, administer, or have explicit permission
  to assess.
- Do not scan public websites, production systems, or infrastructure you do not
  control.
- `-p/--poc` changes WordPress state before attempting best-effort cleanup.
- You are responsible for complying with all applicable laws, regulations, and
  agreements.

* * *

## Features

### Detection workflow

- Scan a single target or a deduplicated list of targets.
- Detect public WordPress HTML, header, and REST API markers.
- Fingerprint exposed WordPress versions when possible.
- Check REST batch behavior and collect structural route markers.
- Use repeated baseline and delayed timing probes for active confirmation.

### Researcher-focused CLI

- Concurrent list scanning with a configurable worker count.
- Clear per-target completion progress and a final status breakdown.
- Color-coded terminal output that automatically remains plain when piped or
  redirected.
- JSON export with optional inclusion of every scan result.
- Quiet multiline command output and verbose PoC response diagnostics.
- Actionable input, network, and response errors.
- Optional command-verification PoC after active confirmation, using `whoami` by
  default or a researcher-supplied command.

* * *

## Requirements

- Python 3.10 or later
- Dependencies listed in `requirements.txt`:
  - `requests`
  - `colorama`

* * *

## Installation

Obtain this repository, then install the dependencies from its root directory.

1. Change to the project directory:

   ```bash
   cd wp2shell-scanner
   ```

2. Optional but recommended: create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   # Windows PowerShell: .venv\Scripts\Activate.ps1
   ```

3. Install dependencies:

   ```bash
   python3 -m pip install -r requirements.txt
   ```

4. Confirm the CLI is available:

   ```bash
   python3 wp2shell-scanner.py -h
   ```

* * *

## Usage

Display help:

```bash
python3 wp2shell-scanner.py -h
```

Running the tool without a target displays the branded help text and exits with
a usage error. Supply exactly one target source: `-u/--url` for one target or
`-l/--list` for a target file.

```bash
python3 wp2shell-scanner.py -u https://wordpress.example
```

Targets without a scheme are treated as `http://` URLs. Target-list files use
one URL per line; blank lines and lines starting with `#` are ignored. Invalid
entries are reported with their line number.

The supported entry point is the root script:

```bash
python3 wp2shell-scanner.py -u https://wordpress.example
```

* * *

## Command-line options

### Targets

| Option | Description | Default |
| --- | --- | --- |
| `-u URL`, `--url URL` | Scan one WordPress target URL. Mutually exclusive with `--list`. | None |
| `-l FILE`, `--list FILE` | Scan target URLs from a text file. Mutually exclusive with `--url`. | None |

### Scan and PoC behavior

| Option | Description | Default |
| --- | --- | --- |
| `-p`, `--poc` | After active confirmation, run the state-changing command-verification PoC. Uses `whoami` unless `--command` is supplied. | Off |
| `-c COMMAND`, `--command COMMAND` | Execute `COMMAND` during `--poc`; requires `--poc`. | `whoami` |
| `-t N`, `--threads N` | Concurrent target workers for a list scan. `N` must be at least `1`. | `10` |

### Output and presentation

| Option | Description | Default |
| --- | --- | --- |
| `-o FILE`, `--output FILE` | Write a UTF-8 JSON array of results to `FILE`. By default, only confirmed vulnerable results are included. | None |
| `--all-results` | Include every scan result in `--output`, including non-vulnerable, not-WordPress, and error results. | Off |
| `-v`, `--verbose` | Show the final PoC HTTP status and `X-Action-Redirect` header. | Off |
| `-q`, `--quiet` | On successful PoC execution, print only normalized command output. Failures and cleanup warnings go to stderr. | Off |
| `--no-color` | Disable colored terminal output. | Off |

* * *

## Examples

Scan one target:

```bash
python3 wp2shell-scanner.py --url https://wordpress.example
```

Scan a target list with 20 workers:

```bash
python3 wp2shell-scanner.py --list targets.txt --threads 20
```

Run the state-changing verification PoC only after the scanner actively confirms
the target:

```bash
python3 wp2shell-scanner.py -u https://wordpress.example -p
```

Run a researcher-supplied command and print only its normalized multiline output:

```bash
python3 wp2shell-scanner.py --url https://wordpress.example -p --command "ls -la" --quiet
```

Write only confirmed vulnerable results to JSON, or include every target with
`--all-results`:

```bash
python3 wp2shell-scanner.py --list targets.txt --output results.json
python3 wp2shell-scanner.py --list targets.txt --output results.json --all-results
```

* * *

## Result interpretation

| Result | Meaning |
| --- | --- |
| **VULNERABLE** | The active timing probe confirmed the vulnerability chain. Patch the target immediately. |
| **POTENTIALLY AFFECTED** | A public version is in an affected range, but active confirmation was blocked or inconclusive. Patch and investigate. |
| **NOT VULNERABLE** | The active probe was not confirmed and no affected public version was detected. |
| **NOT WORDPRESS** | Public WordPress evidence was not found. |
| **ERROR** | A network, TLS, target-input, or unexpected-response error prevented a reliable scan. |

Affected stable releases are WordPress 6.9.0–6.9.4 and 7.0.0–7.0.1. Update to
6.9.5 or 7.0.2, or a later release, immediately.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The scan completed without any `POTENTIALLY AFFECTED` result. Confirmed vulnerable results also use this code. |
| `1` | At least one target is `POTENTIALLY AFFECTED`. |
| `2` | Target input was invalid, or every scheduled target ended in an error. |

* * *

## Credits & acknowledgements

- [Hidden Investigations](https://hiddeninvestigations.net/) – for publishing the wp2Shell scanner and PoC tool.
- [@sakibulalikhan](https://github.com/sakibulalikhan) – tool author.

---

## License

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

📬 Contact us: [hi@hiddeninvestigations.net](mailto:hi@hiddeninvestigations.net)