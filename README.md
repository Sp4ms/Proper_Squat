# Proper_Squat

**Typosquatting domain discovery and registration intelligence using DNSTwist, URLCrazy, WHOIS, and RDAP.**

Proper_Squat is a Python-based command-line reconnaissance tool designed to help security professionals identify potential typosquatting domains associated with a target domain.

It combines the discovery capabilities of [DNSTwist](https://github.com/elceef/dnstwist) and [URLCrazy](https://github.com/urbanadventurer/urlcrazy), deduplicates their results, and enriches discovered domains with registrar and nameserver information obtained through WHOIS and RDAP.

The results are exported to a structured CSV file for further investigation, threat hunting, brand protection, and security reporting.

## Features

- **Multiple discovery engines:** Combines DNSTwist and URLCrazy to identify different types of lookalike domains.
- **Registration intelligence:** Collects registrar and nameserver information for discovered domains.
- **Automatic WHOIS server discovery:** Queries IANA to identify registry WHOIS servers for different top-level domains.
- **RDAP fallback:** Uses RDAP when WHOIS information is missing or incomplete.
- **Registrable-domain detection:** Correctly identifies the parent registration domain of discovered subdomains.
- **Intelligent caching:** Avoids repeated registration lookups for domains sharing the same registrable parent.
- **Request throttling:** Supports configurable delays between outbound registration requests.
- **Optional jitter:** Adds randomized variation to lookup intervals.
- **Result deduplication:** Merges domains discovered by both tools while preserving their typo-generation classifications.
- **CSV reporting:** Produces a four-column report suitable for spreadsheets and further analysis.

## Table of Contents

1. [Why Proper_Squat?](#why-proper_squat)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Usage](#usage)
6. [How It Works](#how-it-works)
7. [CSV Output](#csv-output)
8. [Caching and Rate Limiting](#caching-and-rate-limiting)
9. [Troubleshooting](#troubleshooting)
10. [Limitations](#limitations)
11. [Security Use Cases](#security-use-cases)
12. [Responsible Use](#responsible-use)
13. [Acknowledgments](#acknowledgments)
14. [License](#license)

---

## Why Proper_Squat?

Typosquatting is a technique in which a domain name resembles another domain through misspellings, character substitutions, omissions, additions, or other variations.

For example, a legitimate domain such as:

`example.com`

could have visually or typographically similar alternatives such as:

- `examp1e.com` — character substitution
- `exmaple.com` — character transposition
- `examplle.com` — character repetition
- `examplee.com` — character addition

These examples illustrate potential lookalike patterns; they are not assertions that the domains are registered or malicious.

Lookalike domains can be used for phishing, impersonation, fraudulent email campaigns, brand abuse, or traffic redirection. However, a lookalike domain is not inherently malicious.

### The problem

DNSTwist and URLCrazy are useful domain-generation and discovery tools, but their outputs differ in format and scope.

Investigating their combined results often requires additional manual work:

- Consolidating duplicate domains.
- Identifying which domains merit further investigation.
- Determining the appropriate WHOIS server for each TLD.
- Extracting registrar and nameserver information.
- Handling subdomains whose registration information belongs to a parent domain.
- Managing WHOIS/RDAP request limits.
- Producing a consistent report.

### The solution

Proper_Squat automates this workflow by combining both tools, enriching discovered domains with registration data, and exporting the results to a single CSV file.

It is intended to support initial reconnaissance and triage rather than replace manual investigation.

---

## Requirements

### Operating system

Proper_Squat is primarily designed for **Kali Linux**.

Other Linux distributions may work, but dependency installation and executable paths may differ.

### Software dependencies

| Dependency | Purpose |
|---|---|
| Python 3.10+ | Executes the main script |
| DNSTwist | Generates and identifies potential lookalike domains |
| URLCrazy | Generates additional typo-domain variations and resolution information |
| WHOIS | Queries domain registration databases |
| `tldextract` | Identifies registrable domains using public suffix information |
| Git | Downloads the source repositories |

Python's standard library provides the remaining modules used by the script, including `csv`, `json`, `subprocess`, `urllib`, `argparse`, and `dataclasses`.

### Network requirements

Proper_Squat requires network connectivity for DNS discovery, WHOIS queries, IANA WHOIS server discovery, and RDAP requests.

Depending on the TLD and registration service, outbound access may be needed to:

- DNS resolvers, generally using port 53.
- WHOIS servers, generally using TCP port 43.
- HTTPS-based RDAP services, generally using TCP port 443.

Some networks block outbound WHOIS connections. In these environments, RDAP may still provide useful registration information.

---

## Installation

### Install system dependencies

```bash
sudo apt install -y \
    git \
    python3 \
    python3-tldextract \
    whois \
    dnstwist \
    ruby \
    ruby-dev \
    build-essential
```

Ruby is included because URLCrazy is implemented in Ruby.

Depending on the URLCrazy version and its dependencies, additional Ruby gems may be required. Follow the installation instructions in the upstream URLCrazy repository if it reports missing dependencies.

### Install URLCrazy

Clone the upstream repository:

```bash
sudo git clone https://github.com/urbanadventurer/urlcrazy.git 
```

Install Bundler and Dependencies

```bash
gem install bundler
bundle install
```

Alternatively, if you don't want to install bundler, the following command will install the gem dependencies:

```bash
gem install json colorize async async-dns async-http
```

Verify the installation:

```bash
./urlcrazy --help
```

If URLCrazy reports missing Ruby gems, consult its upstream README and install the dependencies required by that version.

### Download Proper_Squat

Clone your Proper_Squat GitHub repository:

```bash
git clone https://github.com/Sp4ms/Proper_Squat.git
cd Proper_Squat
```

Alternatively, download `Proper_Squat.py` directly and place it in your preferred working directory.

### Verify dependencies

Confirm the installed tool locations:

```bash
which python3
which dnstwist
which whois
```

Check URLCrazy:

```bash
ls -l /opt/urlcrazy/urlcrazy
```

Check the Python dependency:

```bash
python3 -c "import tldextract; print('tldextract OK')"
```

### Step 6: Verify the script

Run:

```bash
python3 Proper_Squat.py --help
```

If the installation is configured correctly, the script should display its available command-line arguments.

---

## Configuration

Proper_Squat uses three configurable executable paths near the beginning of `Proper_Squat.py`:

```python
DNSTWIST_PATH = "/usr/bin/dnstwist"
URLCRAZY_PATH = "/opt/urlcrazy/urlcrazy"
WHOIS_PATH = "/usr/bin/whois"
```

If your tools are installed elsewhere, update these variables.

For example, if URLCrazy is installed in your home directory:

```python
URLCRAZY_PATH = "/home/kali/tools/urlcrazy/urlcrazy"
```

The script validates the configured executables before beginning a scan.

### Timeout settings

The following timeout values can also be modified:

```python
DNSTWIST_TIMEOUT = 3600
URLCRAZY_TIMEOUT = 600
WHOIS_TIMEOUT = 60
RDAP_TIMEOUT = 20
IANA_TIMEOUT = 20
```

These values are measured in seconds.

Large domain-generation scans or slow registry services may require longer timeouts.

### Default request delay

By default, Proper_Squat uses:

```python
DEFAULT_LOOKUP_DELAY = 2.0
DEFAULT_LOOKUP_JITTER = 0.0
```

These defaults can be overridden using command-line arguments without modifying the source code.

---

## Usage

### Basic scan

```bash
python3 Proper_Squat.py example.com
```

This runs DNSTwist and URLCrazy against `example.com`, performs registration lookups for qualifying results, and generates:

`example.com-typos.csv`

### Specify an output filename

```bash
python3 Proper_Squat.py example.com -o results.csv
```

### Increase the lookup delay

```bash
python3 Proper_Squat.py example.com --lookup-delay 5
```

This configures a minimum five-second interval between the start times of outbound registration requests.

### Add randomized jitter

```bash
python3 Proper_Squat.py example.com \
    --lookup-delay 3 \
    --lookup-jitter 1
```

This uses a minimum three-second interval with up to one additional second of randomized delay.

### Disable throttling

```bash
python3 Proper_Squat.py example.com --lookup-delay 0
```

This disables the configured minimum interval. It is not recommended for large scans because WHOIS and RDAP services may enforce request limits.

### Full example

```bash
python3 Proper_Squat.py example.com \
    --lookup-delay 5 \
    --lookup-jitter 1 \
    -o example-results.csv
```

### Command-line options

| Argument | Description | Default |
|---|---|---|
| `domain` | Domain to analyze | Required |
| `-o`, `--output` | Output CSV filename | `<domain>-typos.csv` |
| `--lookup-delay` | Minimum interval between outbound registration requests, in seconds | `2.0` |
| `--lookup-jitter` | Maximum additional randomized interval, in seconds | `0.0` |
| `-h`, `--help` | Display command-line help | — |

Both delay values must be between 0 and 3600 seconds.

---

## How It Works

Proper_Squat performs discovery, deduplication, registration enrichment, and reporting.

### Workflow overview

```text
                    Target Domain
                         |
                         v
                Original WHOIS/RDAP
                         |
                         v
              +---------------------+
              |                     |
              v                     v
           DNSTwist              URLCrazy
              |                     |
              v                     v
       Registered-filtered     NS/MX-resolved
          candidates             candidates
              |                     |
              +----------+----------+
                         |
                         v
                Merge and Deduplicate
                         |
                         v
              Extract Registrable Domain
                         |
                         v
                Check Registration Cache
                         |
                +--------+--------+
                |                 |
             Cache Hit         Cache Miss
                |                 |
                |                 v
                |           Standard WHOIS
                |                 |
                |          Missing information?
                |                 |
                |                 v
                |        IANA WHOIS Discovery
                |                 |
                |          Missing information?
                |                 |
                |                 v
                |            RDAP Fallback
                |                 |
                |                 v
                |           Merge and Cache
                |                 |
                +--------+--------+
                         |
                         v
                   CSV Export
```

### 1. Original domain lookup

Proper_Squat begins by collecting registration information for the supplied domain.

The original domain is included as the first data row in the CSV, labeled `*Original`.

This provides a reference point for comparing discovered domains against the legitimate domain's registration information.

### 2. DNSTwist discovery

Proper_Squat executes DNSTwist using:

```bash
dnstwist --registered --format json example.com
```

DNSTwist generates lookalike-domain variations and applies its registered-domain filtering.

The script parses the JSON output and collects returned candidate domains along with their fuzzing classifications.

**Why use DNSTwist?**

DNSTwist provides a broad set of domain mutation techniques and helps identify variations that could be relevant to phishing, brand impersonation, and defensive domain monitoring.

### 3. URLCrazy discovery

Proper_Squat executes URLCrazy using:

```bash
urlcrazy -f JSON example.com
```

The script parses the `typos` array from URLCrazy's JSON output.

A URLCrazy candidate is included when its `resolved_ns` or `resolved_mx` field contains a non-empty value.

**Why use URLCrazy?**

URLCrazy provides additional typo-generation methods that can complement DNSTwist.

Combining the two tools can improve discovery coverage compared with relying on a single generation engine.

**Important:** DNS resolution is not definitive proof of registration or malicious activity. URLCrazy's resolution-based filtering is a candidate-selection mechanism, not an authoritative registration check.

### 4. Deduplication

A candidate may be identified by both DNSTwist and URLCrazy.

Proper_Squat merges results by normalized hostname so that each unique discovered hostname appears only once in the CSV.

If multiple typo-generation techniques identify the same hostname, their classifications are retained and combined in the `Typo-Type` column.

### 5. Registrable-domain extraction

Some discovered hostnames are subdomains rather than independently registered domains.

For example:

```text
Discovered hostname: te.st.com
Registrable domain:  st.com
```

A WHOIS query against `te.st.com` may not return meaningful registration information because the registration belongs to `st.com`.

Proper_Squat uses `tldextract` to identify the registrable parent domain before querying WHOIS or RDAP.

This also handles multi-label public suffixes:

```text
Discovered hostname: fake.example.co.uk
Registrable domain:  example.co.uk
```

The full discovered hostname remains unchanged in the CSV.

### 6. Standard WHOIS lookup

The first registration lookup uses the configured WHOIS executable:

```bash
whois example.com
```

Proper_Squat attempts to extract:

- Registrar
- Nameservers

WHOIS output is unstructured and varies between registries, so the script uses multiple regular-expression patterns to identify common field names.

### 7. IANA WHOIS server discovery

If the standard WHOIS response is missing a registrar or nameservers, Proper_Squat attempts to discover the registry WHOIS server using IANA.

For example, to inspect the `.ws` registry information manually:

```bash
whois -h whois.iana.org ws
```

When IANA advertises a WHOIS server, Proper_Squat queries that server directly.

**Why is this useful?**

Different TLD registries may use different WHOIS services, and a default WHOIS client may not always retrieve the information needed.

IANA discovery reduces the need to maintain a hardcoded list of WHOIS servers.

### 8. RDAP fallback

If WHOIS results remain incomplete, Proper_Squat attempts an RDAP lookup.

RDAP is a structured registration-data protocol that typically returns JSON.

The script retrieves IANA's RDAP bootstrap registry from:

https://data.iana.org/rdap/dns.json

It then identifies the appropriate RDAP service for the TLD and requests registration information.

For domain objects, Proper_Squat extracts registrar information from entities with a `registrar` role and nameservers from the `nameservers` array.

**Why RDAP?**

RDAP provides a structured alternative to WHOIS and may expose information that was unavailable or difficult to parse in the text-based WHOIS response.

However, RDAP coverage and the availability of individual fields vary by registry.

### 9. Merge registration information

Proper_Squat combines information retrieved from different sources.

The current implementation:

- Preserves the first non-empty registrar value.
- Combines distinct nameserver values.
- Uses RDAP to supplement missing WHOIS fields.

This can improve coverage, but conflicting data from different registration services may require manual validation.

### 10. Export results

After processing the discovered domains, Proper_Squat writes the results to a CSV file.

The original domain appears first, followed by the deduplicated discovered hostnames in alphabetical order.

---

## CSV Output

Proper_Squat generates exactly four columns:

| Column | Description |
|---|---|
| `Typo-Type` | Typo-generation classification or `*Original` |
| `Domain` | Original domain or full discovered hostname |
| `Registrar` | Registrar identified through WHOIS or RDAP |
| `Name-Servers` | Collected nameservers, separated by commas |

### Example output

The following is illustrative data, not actual registration intelligence:

```csv
Typo-Type,Domain,Registrar,Name-Servers
*Original,example.com,Example Registrar,"ns1.example.net, ns2.example.net"
Addition,examplee.com,Sample Registrar,"ns1.example.org, ns2.example.org"
Transposition,exmaple.com,Sample Registrar,ns1.example.org
```

CSV fields containing commas are quoted automatically to preserve the four-column structure.

### Interpreting results

A registrar or nameserver match between domains may help identify shared infrastructure or registration patterns.

However, shared infrastructure does not establish common ownership, and different registration information does not establish malicious intent.

Blank registrar or nameserver fields indicate that the tool could not extract those values from the available responses.

They do not necessarily mean that a domain is unregistered.

---

## Caching and Rate Limiting

### Registration cache

Proper_Squat caches successful registration lookups by registrable domain.

For example:

```text
te.st.com  -> st.com
tes.st.com -> st.com
```

Both hostnames use registration information associated with `st.com`.

Once a successful result is cached, subsequent lookups for that registrable domain reuse the cached information.

### WHOIS server cache

IANA WHOIS server discovery results are cached by TLD.

For example, after discovering a server for `.ws`, the script does not need to repeat the IANA discovery request for every additional `.ws` candidate during the same execution.

### RDAP server cache

RDAP service discovery results are also cached by TLD.

The IANA RDAP bootstrap document is loaded once per execution.

### Cache persistence

All caches are maintained in memory.

They are reset when the script exits.

The current version does not persist cached registration information to disk.

### Lookup throttling

The script implements a global minimum interval between the start times of outbound registration lookup requests.

The following requests are throttled:

- Standard WHOIS lookups.
- IANA WHOIS server discovery requests.
- Direct registry WHOIS lookups.
- RDAP domain registration requests.

The IANA RDAP bootstrap download is not throttled.

DNSTwist and URLCrazy's internal DNS requests are not controlled by this throttle.

If an individual request takes longer than the configured interval, the next request may begin without an additional sleep.

### Rate-limit considerations

WHOIS and RDAP services may enforce request limits, block repeated queries, or return incomplete responses.

Increasing the lookup delay may reduce request frequency, but it does not guarantee that a registry will accept every request.

The current version does not implement automatic HTTP 429 retry handling, per-registry rate-limit policies, or persistent retry queues.

---

## Troubleshooting

### DNSTwist not found

Example:

```text
[!] DNSTwist not found: /usr/bin/dnstwist
```

Check the executable location:

```bash
which dnstwist
```

Update `DNSTWIST_PATH` in the script if necessary.

### URLCrazy not found

Example:

```text
[!] URLCrazy not found: /opt/urlcrazy/urlcrazy
```

Verify the file exists:

```bash
ls -l /opt/urlcrazy/urlcrazy
```

If it is installed elsewhere, update `URLCRAZY_PATH`.

### WHOIS not found

Install WHOIS:

```bash
sudo apt install whois
```

Then verify:

```bash
which whois
```

### Missing `tldextract`

Example:

```text
ModuleNotFoundError: No module named 'tldextract'
```

Install the Kali package:

```bash
sudo apt install python3-tldextract
```

Make sure the Python interpreter running Proper_Squat can import the module.

### URLCrazy JSON parsing warnings

Some URLCrazy versions may emit warning text before their JSON output.

Proper_Squat attempts to locate and parse the JSON document even when such warnings are present.

If the output contains no valid JSON, the script reports a parsing error and continues with whatever results are available from the other discovery engine.

### Missing registrar or nameservers

A domain may have missing registration fields because:

- The WHOIS server returned limited information.
- The registry uses an unsupported WHOIS field format.
- The WHOIS service is unavailable.
- The RDAP service did not return the requested field.
- The registry restricted or rate-limited the request.
- The domain is not registered.

Proper_Squat attempts multiple lookup methods, but it cannot guarantee complete registration data for every TLD.

### WHOIS connection timeouts

Test WHOIS connectivity:

```bash
whois example.com
```

You can also inspect IANA information:

```bash
whois -h whois.iana.org ws
```

If WHOIS connections consistently fail, check firewall restrictions and outbound TCP port 43 access.

### RDAP request failures

Check whether the IANA bootstrap registry is accessible:

```bash
curl -I https://data.iana.org/rdap/dns.json
```

RDAP lookups can fail because of network restrictions, unsupported TLDs, unavailable endpoints, or registry-side rate limits.

### Slow scans

Large scans can take time because of:

- DNSTwist and URLCrazy domain generation.
- DNS resolution.
- WHOIS timeouts.
- RDAP fallback requests.
- Configured lookup delays.
- Registry-side throttling.

For example, if a scan produces hundreds of unique registrable domains, the registration-enrichment stage may take considerably longer than the initial discovery stage.

---

## Limitations

Proper_Squat is a reconnaissance and reporting tool, not a definitive domain-registration or malicious-domain classification service.

Known limitations include:

**Registration coverage:** WHOIS and RDAP availability varies by TLD. Some registries provide limited or no public registrar information.

**WHOIS parsing:** The current parser recognizes common field formats but may miss registry-specific nameserver or registrar fields.

**Discovery filtering:** DNSTwist uses its registered-domain filter, while URLCrazy candidates are selected based on non-empty NS or MX resolution fields. These mechanisms do not provide identical guarantees.

**No maliciousness determination:** The presence of a lookalike domain does not mean that it is being used maliciously.

**No live website inspection:** Proper_Squat does not visit discovered websites, analyze their HTML, inspect TLS certificates, capture screenshots, or determine whether they host phishing content.

**No email-security assessment:** Although URLCrazy resolution information can help select candidates, the tool does not perform a comprehensive MX, SPF, DKIM, or DMARC assessment.

**In-memory caching:** Cached results do not persist between runs.

**Global throttling:** The delay is applied to registration requests initiated by the Python script, not to every network request made by DNSTwist or URLCrazy.

**Potentially inconsistent nameservers:** Nameservers collected from multiple registration sources may reflect differing data. The tool does not independently validate the current authoritative DNS delegation.

**Internationalized domains:** Domain handling and validation may not cover every internationalized domain-name representation.

**Public suffix data:** `tldextract` relies on public suffix information, which may require a first-use download or use locally cached data.

---

## Security Use Cases

### Brand protection

Identify domains resembling an organization's legitimate domains for investigation and potential defensive monitoring.

### Phishing reconnaissance

Discover lookalike domains that may warrant further review for impersonation or phishing activity.

### Threat hunting

Generate candidate domain sets that can be compared against DNS logs, proxy logs, email telemetry, or threat intelligence platforms.

### Domain registration analysis

Compare registrar and nameserver information across discovered domains to identify possible infrastructure relationships.

### Security assessments

Support authorized reconnaissance during security assessments and brand-abuse investigations.

### Continuous monitoring

Proper_Squat can serve as a starting point for a broader monitoring workflow, although the current script does not provide built-in scheduling, historical comparisons, or alerting.

---

## Responsible Use

Proper_Squat is intended for legitimate security research, authorized assessments, brand protection, and defensive monitoring.

Only perform testing that is permitted by applicable laws, organizational policies, and service-provider terms.

The tool generates DNS and registration-service queries. Large scans may place load on external services or trigger rate limits.

Users are responsible for configuring appropriate request intervals and handling the resulting data responsibly.

Discovery of a lookalike domain should be treated as an investigative lead, not proof of malicious activity.

---

## Acknowledgments

Proper_Squat builds on the capabilities and public infrastructure provided by:

- [DNSTwist](https://github.com/elceef/dnstwist) — Domain typo generation and discovery.
- [URLCrazy](https://github.com/urbanadventurer/urlcrazy) — Domain typo generation and resolution analysis.
- [tldextract](https://github.com/john-kurkowski/tldextract) — Registrable-domain and public-suffix extraction.
- [IANA](https://www.iana.org/) — TLD registration information and RDAP bootstrap data.
- [RDAP](https://www.rfc-editor.org/rfc/rfc9082.html) — Structured domain registration data access.

Proper_Squat is an independent wrapper and enrichment tool. It is not affiliated with or endorsed by these projects or organizations.

---

**Proper_Squat — Discover the lookalikes. Enrich the intelligence. Investigate the risk.**
