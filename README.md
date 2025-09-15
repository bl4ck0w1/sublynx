# SubLynx

![sublynx-logo](docs/logo.png)

**SubLynx** is an advanced, stealth-friendly subdomain discovery and validation platform built for security engineers, red teams, and bug bounty workflows. It combines multi-source discovery (CT logs, passive intel, permutations), layered validation, and clean reporting — with rate control and scheduling engineered for reliability at scale.

---

## Why SubLynx?

Existing enumerators are great, but they often trade verification quality for speed or lack the guardrails needed for long, unattended runs. **SubLynx** is designed for production-grade, high-signal discovery:

* **Low Noise, Higher Signal** — Layered validation (DNS/HTTP/content) and risk scoring to minimize false positives.
* **Stealth & Control** — Optional “stealth mode” with timing jitter and request masquerading to reduce detection.
* **Modular Workflows** — Composable discovery/validation workflows so you can mix CT, passive, permutations, and more.
* **Resource-Aware** — Adaptive rate limiting and a priority scheduler to keep hosts (and your box) happy.

> ⚠️ **Ethics & Scope**: Use **only** with explicit permission. Respect rate limits, robots, and all legal constraints.

---

## Features at a Glance

* **Multi-Source Discovery**: Certificate Transparency, Passive intel, and Permutation engines.
* **Validation Layers**: DNS, HTTP (headers/title/status/tech), content checks, SSL info snapshot, and basic security probes.
* **Risk Model**: Simple, explainable risk scoring on subdomains and findings.
* **Scheduler**: Priority queue with exponential backoff for flaky tasks; configurable concurrency.
* **Resource Optimizer**: Adaptive rate limiting based on CPU/mem/network signals.
* **Reporting**: Human-readable TXT/CSV/JSON summaries and a clean terminal UX.
* **Configuration Profiles**: Manage profiles under `~/.sublynx/` and switch them via flags.

---

## Quick Start

### Requirements

* **Go** ≥ 1.21 (tested with 1.22+)
* Linux/macOS/WSL2 recommended

### Build

```bash
# clone
git clone https://github.com/bl4ck0w1/sublynx.git
cd sublynx

# build the CLI
go build -o bin/sublynx ./cmd/sublynx
```

### Install (optional)

```bash
# from the repo root
go install ./cmd/sublynx

```

---

## CLI Reference (`--help`)

> SubLynx prints a consolidated, full-page help at the root level and normal focused help at subcommands.

```
echo "   ▄████████ ███    █▄  ▀█████████▄   ▄█       ▄██   ▄   ███▄▄▄▄   ▀████    ▐████▀ ";
echo "  ███    ███ ███    ███   ███    ███ ███       ███   ██▄ ███▀▀▀██▄   ███▌   ████▀  ";
echo "  ███    █▀  ███    ███   ███    ███ ███       ███▄▄▄███ ███   ███    ███  ▐███    ";
echo "  ███        ███    ███  ▄███▄▄▄██▀  ███       ▀▀▀▀▀▀███ ███   ███    ▀███▄███▀    ";
echo "▀███████████ ███    ███ ▀▀███▀▀▀██▄  ███       ▄██   ███ ███   ███    ████▀██▄     ";
echo "         ███ ███    ███   ███    ██▄ ███       ███   ███ ███   ███   ▐███  ▀███    ";
echo "   ▄█    ███ ███    ███   ███    ███ ███▌    ▄ ███   ███ ███   ███  ▄███     ███▄  ";
echo " ▄████████▀  ████████▀  ▄█████████▀  █████▄▄██  ▀█████▀   ▀█   █▀  ████       ███▄ ";
echo "                                     ▀                                             ";
	

						Advanced Subdomain Discovery Platform
			______________________________________________________________

Usage:
  sublynx [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  configure   Manage SubLynx configuration
  output      Manage output and reports
  scan        Perform subdomain discovery and analysis
  stats       Show runtime statistics
  version     Print version information

Global Flags:
  -c, --config string      config file (default is $HOME/.sublynx/config.yaml)
  -q, --quiet              quiet mode (no banner output)
  -l, --log-level string   log level (debug, info, warn, error, fatal) (default "info")
      --log-format string  log format (text, json) (default "json")
      --log-file string    log file path
  -v, --version            version for sublynx
```

**Scan Command**

```
Perform comprehensive subdomain discovery, validation, and security analysis.

Usage:
  sublynx scan [domain] [flags]

Flags:
  -m, --methods strings        Discovery methods (all, ct, passive, permutations, ai) (default [all])
  -v, --validation strings     Validation methods (all, dns, http, security) (default [all])
  -d, --depth int              Permutation depth (default 2)
  -t, --timeout int            Scan timeout in minutes (default 30)
      --stealth                Enable stealth mode (slower, less detectable)
      --no-validation          Skip validation phase
      --no-security            Skip security checks
  -o, --output string          Output file path
  -f, --formats strings        Output formats (default [txt,csv])

Global Flags:
  -c, --config string      config file (default is $HOME/.sublynx/config.yaml)
  -l, --log-level string   log level (debug, info, warn, error, fatal) (default "info")
      --log-format string  log format (text, json) (default "json")
      --log-file string    log file path
  -q, --quiet              quiet mode (no banner output)

```

**Configure & Output Commands**

```
sublynx configure [get|init|list|set|show]  # Manage profiles under ~/.sublynx/
sublynx output    [cleanup|generate|list|stats|view]  # Work with reports
```

---

## Usage Examples

### 1) Minimal scan

```bash
bin/sublynx scan example.com
```

### 2) Stealth scan with deeper permutations and multiple formats

```bash
bin/sublynx scan example.com --stealth -d 3 -f txt,csv,json
```

### 3) Control discovery/validation explicitly

```bash
bin/sublynx scan example.com \
  --methods ct,passive,permutations \
  --validation dns,http,security
```

### 4) Skip validation (discovery only)

```bash
bin/sublynx scan example.com --no-validation
```

### 5) Configure profiles

```bash
# initialize default profile
bin/sublynx configure init

# show active configuration
bin/sublynx configure show

# set a value in the default profile
bin/sublynx configure set log_level debug --profile default
```

### 6) Work with reports

```bash
# list reports
bin/sublynx output list

# view a specific report (by scan-id + format)
bin/sublynx output view scan_example.com_20231201_143022 --format txt

# generate exports (if re-running generator)
bin/sublynx output generate scan_example.com_20231201_143022 -f txt,csv

# cleanup old reports (> 30 days)
bin/sublynx output cleanup --older-than 720h
```

### 7) Stats & Version

```bash
bin/sublynx stats
bin/sublynx version
```
---

## FAQ

**1) Does SubLynx avoid false positives?**
Yes — through staged validation, header/title/SSL snapshots, content length/timing checks, and basic security probing. Reports include enough context to revalidate externally.

**2) Can I run this “quietly”?**
Use `--quiet` to suppress the banner. Stealth mode (`--stealth`) also paces requests and adjusts headers/behaviors to reduce detection.

**3) Can I customize rate limits and concurrency?**
Yes — via config (`max_concurrent_scans`, timeouts) and the internal resource optimizer which can adapt limits based on system usage.

**4) Is there an API?**
API hooks are scaffolded (models + config). Public API endpoints may be added in a later release.

**5) Can I plug in my own discovery/validation method?**
Yes — the workflow manager supports registering custom discovery/validation workflows.

---

## Contributing

PRs are welcome! Please include:

* Reproducible steps or test cases
* Before/after performance or noise comparisons (where applicable)
* Documentation updates for any new flags or config fields

---

## 🛠️ Troubleshooting

* Run with `--log-level debug` for more verbose logs.
* Ensure `~/.sublynx/config.yaml` exists (use `sublynx configure init`).
* Check filesystem permissions for `output_directory` and `data_directory`.
* If something’s off, please open an issue on GitHub.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

**Elie Uwimana 😎**

* [LinkedIn](https://www.linkedin.com/in/elie-uwimana)

---

## Compliance & Ethics

⚠️ **Authorized Use Only** — SubLynx is designed for:

* Penetration testing with written permission
* Bug bounty programs within platform rules
* Government cybersecurity operations (lawful use)
* Academic research in controlled environments

Always obtain permission and follow all applicable laws and policies.
