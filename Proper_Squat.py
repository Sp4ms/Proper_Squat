
#!/usr/bin/env python3

"""
Proper_Squat

Discover potential typosquatting domains using DNSTwist and URLCrazy.

Enrich discovered domains using:
    1. Standard WHOIS
    2. IANA-discovered registry WHOIS
    3. RDAP fallback

Features:
    - Registrable-domain extraction
    - WHOIS result caching
    - WHOIS server discovery caching
    - RDAP server discovery caching
    - Configurable registration lookup delay
    - Optional lookup jitter
    - Four-column CSV export

CSV:
    Typo-Type,Domain,Registrar,Name-Servers

Examples:
    python3 Proper_Squat.py example.com

    python3 Proper_Squat.py example.com \
        --lookup-delay 3

    python3 Proper_Squat.py example.com \
        --lookup-delay 3 \
        --lookup-jitter 1 \
        -o results.csv
"""

import argparse
import csv
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tldextract


# ============================================================
# CONFIGURATION
# ============================================================

DNSTWIST_PATH = "/usr/bin/dnstwist"
URLCRAZY_PATH = "/opt/urlcrazy/urlcrazy"
WHOIS_PATH = "/usr/bin/whois"

DNSTWIST_TIMEOUT = 3600
URLCRAZY_TIMEOUT = 600
WHOIS_TIMEOUT = 60
RDAP_TIMEOUT = 20
IANA_TIMEOUT = 20

IANA_WHOIS_SERVER = "whois.iana.org"

RDAP_BOOTSTRAP_URL = (
    "https://data.iana.org/rdap/dns.json"
)

USER_AGENT = "Proper-Squat/1.1"

# Default minimum interval between registration requests.
DEFAULT_LOOKUP_DELAY = 2.0

# Default additional randomized delay.
DEFAULT_LOOKUP_JITTER = 0.0

DOMAIN_RE = re.compile(
    r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9-]{2,63}$"
)

WHOIS_REGISTRAR_PATTERNS = [
    re.compile(r"(?im)^\s*Registrar:\s*(.+?)\s*$"),
    re.compile(r"(?im)^\s*Registrar Name:\s*(.+?)\s*$"),
    re.compile(r"(?im)^\s*Sponsoring Registrar:\s*(.+?)\s*$"),
    re.compile(r"(?im)^\s*Registrar Organization:\s*(.+?)\s*$"),
]

WHOIS_NS_PATTERNS = [
    re.compile(r"(?im)^\s*Name Servers?:\s*(\S+)\s*$"),
    re.compile(r"(?im)^\s*Nserver:\s*(\S+)(?:\s+.*)?$"),
    re.compile(r"(?im)^\s*Nameserver:\s*(\S+)(?:\s+.*)?$"),
    re.compile(r"(?im)^\s*Name-server:\s*(\S+)\s*$"),
]


# ============================================================
# CACHES
# ============================================================

# Registrable domain -> (registrar, nameservers)
WHOIS_CACHE: dict[str, tuple[str, list[str]]] = {}

# TLD -> WHOIS server or None
WHOIS_SERVER_CACHE: dict[str, str | None] = {}

# TLD -> RDAP service endpoints
RDAP_SERVER_CACHE: dict[str, list[str]] = {}

# IANA RDAP bootstrap registry
RDAP_BOOTSTRAP_CACHE: dict[str, Any] | None = None


# ============================================================
# LOOKUP THROTTLING
# ============================================================

@dataclass
class LookupThrottle:
    """
    Enforce a minimum interval between outbound registration
    lookup requests.

    Delay is measured between request start times.

    If a request itself takes longer than the configured delay,
    the next request can begin immediately.

    Jitter adds a random interval between 0 and the configured
    jitter value.
    """

    delay: float = DEFAULT_LOOKUP_DELAY
    jitter: float = DEFAULT_LOOKUP_JITTER
    last_request: float | None = None

    def wait(self) -> None:
        if self.last_request is not None:
            target_interval = self.delay

            if self.jitter > 0:
                target_interval += random.uniform(
                    0,
                    self.jitter,
                )

            elapsed = (
                time.monotonic()
                - self.last_request
            )

            remaining = target_interval - elapsed

            if remaining > 0:
                log(
                    f"    [RATE LIMIT] Waiting "
                    f"{remaining:.2f}s before next lookup..."
                )

                time.sleep(remaining)

        self.last_request = time.monotonic()


LOOKUP_THROTTLE = LookupThrottle()


# ============================================================
# DOMAIN RECORD
# ============================================================

@dataclass
class DomainRecord:
    domain: str
    typo_types: list[str] = field(default_factory=list)
    registrar: str = ""
    nameservers: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)

    def add_type(self, value: str) -> None:
        value = normalize_typo_type(value)

        if value and value not in self.typo_types:
            self.typo_types.append(value)

    def add_nameservers(self, values: list[str]) -> None:
        existing = {
            ns.lower()
            for ns in self.nameservers
        }

        for value in values:
            ns = normalize_nameserver(value)

            if (
                ns
                and DOMAIN_RE.fullmatch(ns)
                and ns not in existing
            ):
                self.nameservers.append(ns)
                existing.add(ns)


# ============================================================
# GENERAL HELPERS
# ============================================================

def log(message: str) -> None:
    print(message, file=sys.stderr)


def normalize_domain(value: str) -> str:
    value = value.strip().lower()

    value = re.sub(
        r"^[a-z][a-z0-9+.-]*://",
        "",
        value,
        flags=re.IGNORECASE,
    )

    value = value.split("/", 1)[0]

    if ":" in value:
        value = value.split(":", 1)[0]

    return value.rstrip(".")


def normalize_nameserver(value: str) -> str:
    return value.strip().strip(".,;").lower().rstrip(".")


def normalize_typo_type(value: str) -> str:
    value = str(value).strip()

    if not value:
        return "Unknown"

    value = value.replace("_", " ").replace("-", " ")
    value = re.sub(r"\s+", " ", value)

    return value.title()


def get_whois_domain(domain: str) -> str:
    """
    Return the registrable domain.

    te.st.com          -> st.com
    fake.example.co.uk -> example.co.uk
    example.com        -> example.com
    """

    domain = normalize_domain(domain)

    extracted = tldextract.extract(domain)

    if extracted.domain and extracted.suffix:
        return (
            f"{extracted.domain}."
            f"{extracted.suffix}"
        )

    return domain


def get_tld(domain: str) -> str:
    extracted = tldextract.extract(domain)

    if extracted.suffix:
        return extracted.suffix.rsplit(".", 1)[-1].lower()

    return domain.rsplit(".", 1)[-1].lower()


def validate_tool_path(name: str, path: str) -> bool:
    if "/" in path:
        tool_path = Path(path)

        if not tool_path.is_file():
            log(f"[!] {name} not found: {path}")
            return False

        if not os.access(tool_path, os.X_OK):
            log(f"[!] {name} is not executable: {path}")
            return False

        return True

    if shutil.which(path) is None:
        log(f"[!] {name} not found in PATH: {path}")
        return False

    return True


def run_command(
    command: list[str],
    timeout: int = 60,
    throttle: bool = False,
) -> subprocess.CompletedProcess:
    """
    Execute an external command.

    Set throttle=True for outbound WHOIS registration requests.

    DNSTwist and URLCrazy themselves are not throttled here.
    """

    if throttle:
        LOOKUP_THROTTLE.wait()

    try:
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )

    except subprocess.TimeoutExpired:
        log(
            f"[!] Command timed out: {' '.join(command)}"
        )

        return subprocess.CompletedProcess(
            command,
            124,
            "",
            "Command timed out",
        )

    except OSError as exc:
        log(f"[!] Command execution failed: {exc}")

        return subprocess.CompletedProcess(
            command,
            1,
            "",
            str(exc),
        )


def parse_json_output(
    output: str,
    tool_name: str,
) -> Any:
    """
    Parse JSON, including output preceded by warning text.
    """

    output = output.strip()

    if not output:
        log(f"[!] {tool_name} returned no output.")
        return None

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()

    for match in re.finditer(r"[\{\[]", output):
        position = match.start()

        try:
            data, end = decoder.raw_decode(
                output[position:]
            )

            if position:
                log(
                    f"[!] {tool_name}: Ignored text "
                    f"preceding JSON."
                )

                log(
                    f"    {output[:position].strip()[:500]}"
                )

            if output[position + end:].strip():
                log(
                    f"[!] {tool_name}: Ignored trailing text."
                )

            return data

        except json.JSONDecodeError:
            continue

    log(f"[!] Unable to parse {tool_name} JSON.")
    log(f"[!] First 500 bytes:\n{output[:500]}")

    return None


# ============================================================
# HTTP / JSON
# ============================================================

def fetch_json(
    url: str,
    timeout: int = RDAP_TIMEOUT,
    throttle: bool = False,
) -> Any:
    """
    Fetch JSON using urllib.

    Set throttle=True for RDAP registration requests.

    IANA bootstrap downloads are not counted as registration
    lookups and therefore are not throttled.
    """

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rdap+json, application/json",
        },
    )

    if throttle:
        LOOKUP_THROTTLE.wait()

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            raw = response.read(
                10 * 1024 * 1024
            )

        return json.loads(
            raw.decode("utf-8-sig")
        )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        ValueError,
        UnicodeError,
    ) as exc:
        log(f"    [HTTP] Failed {url}: {exc}")
        return None


# ============================================================
# WHOIS PARSING
# ============================================================

def parse_whois(
    output: str,
) -> tuple[str, list[str]]:
    registrar = ""
    nameservers: list[str] = []

    for pattern in WHOIS_REGISTRAR_PATTERNS:
        match = pattern.search(output)

        if match:
            value = match.group(1).strip()

            if value:
                registrar = value
                break

    for pattern in WHOIS_NS_PATTERNS:
        for match in pattern.finditer(output):
            ns = normalize_nameserver(
                match.group(1)
            )

            if DOMAIN_RE.fullmatch(ns):
                nameservers.append(ns)

    return registrar, sorted(set(nameservers))


def merge_registration_data(
    current_registrar: str,
    current_nameservers: list[str],
    new_registrar: str,
    new_nameservers: list[str],
) -> tuple[str, list[str]]:
    """
    Preserve the first non-empty registrar and merge
    distinct nameservers.
    """

    registrar = current_registrar or new_registrar

    nameservers = sorted(
        set(current_nameservers)
        | set(new_nameservers)
    )

    return registrar, nameservers


# ============================================================
# IANA WHOIS SERVER DISCOVERY
# ============================================================

def discover_whois_server(
    domain: str,
) -> str | None:
    """
    Query IANA to discover the WHOIS server for a TLD.

    Cache results by TLD.
    """

    tld = get_tld(domain)

    if tld in WHOIS_SERVER_CACHE:
        return WHOIS_SERVER_CACHE[tld]

    log(
        f"    [WHOIS DISCOVERY] Querying IANA for .{tld}"
    )

    result = run_command(
        [
            WHOIS_PATH,
            "-h",
            IANA_WHOIS_SERVER,
            tld,
        ],
        timeout=IANA_TIMEOUT,
        throttle=True,
    )

    match = re.search(
        r"(?im)^\s*whois:\s*(\S+)\s*$",
        result.stdout,
    )

    server = (
        match.group(1).strip()
        if match
        else None
    )

    if server:
        server = server.rstrip(".").lower()

        if not DOMAIN_RE.fullmatch(server):
            log(
                f"    [WHOIS DISCOVERY] "
                f"Invalid server returned: {server}"
            )
            server = None

    WHOIS_SERVER_CACHE[tld] = server

    if server:
        log(
            f"    [WHOIS DISCOVERY] "
            f".{tld} -> {server}"
        )
    else:
        log(
            f"    [WHOIS DISCOVERY] "
            f"No WHOIS server advertised for .{tld}"
        )

    return server


# ============================================================
# RDAP BOOTSTRAP DISCOVERY
# ============================================================

def load_rdap_bootstrap() -> dict[str, Any]:
    """
    Download IANA's RDAP DNS bootstrap registry once.
    """

    global RDAP_BOOTSTRAP_CACHE

    if RDAP_BOOTSTRAP_CACHE is not None:
        return RDAP_BOOTSTRAP_CACHE

    log(
        "    [RDAP] Loading IANA RDAP bootstrap registry..."
    )

    data = fetch_json(
        RDAP_BOOTSTRAP_URL,
        timeout=IANA_TIMEOUT,
        throttle=False,
    )

    if not isinstance(data, dict):
        data = {}

    RDAP_BOOTSTRAP_CACHE = data

    return data


def discover_rdap_servers(
    domain: str,
) -> list[str]:
    """
    Find RDAP service URLs for a domain's TLD.
    """

    tld = get_tld(domain)

    if tld in RDAP_SERVER_CACHE:
        return RDAP_SERVER_CACHE[tld]

    bootstrap = load_rdap_bootstrap()

    services = bootstrap.get(
        "services",
        [],
    )

    urls: list[str] = []

    if isinstance(services, list):
        for entry in services:
            if (
                not isinstance(entry, list)
                or len(entry) < 2
            ):
                continue

            suffixes, endpoints = entry[0], entry[1]

            if not isinstance(suffixes, list):
                continue

            if not isinstance(endpoints, list):
                continue

            normalized_suffixes = {
                str(value).lower().lstrip(".")
                for value in suffixes
            }

            if tld not in normalized_suffixes:
                continue

            for endpoint in endpoints:
                if not isinstance(endpoint, str):
                    continue

                parsed = urllib.parse.urlsplit(
                    endpoint
                )

                if (
                    parsed.scheme == "https"
                    and parsed.hostname
                ):
                    urls.append(endpoint)

    urls = list(dict.fromkeys(urls))

    RDAP_SERVER_CACHE[tld] = urls

    if urls:
        log(
            f"    [RDAP DISCOVERY] "
            f".{tld} -> {', '.join(urls)}"
        )
    else:
        log(
            f"    [RDAP DISCOVERY] "
            f"No RDAP endpoint found for .{tld}"
        )

    return urls


# ============================================================
# RDAP PARSING
# ============================================================

def extract_vcard_organization(
    entity: dict[str, Any],
) -> str:
    """
    Extract an organization or formatted name from jCard.
    """

    vcard = entity.get(
        "vcardArray"
    )

    if (
        not isinstance(vcard, list)
        or len(vcard) < 2
        or not isinstance(vcard[1], list)
    ):
        return ""

    properties = vcard[1]

    for wanted in ("org", "fn"):
        for property_item in properties:
            if (
                not isinstance(property_item, list)
                or len(property_item) < 4
            ):
                continue

            key = str(
                property_item[0]
            ).lower()

            if key != wanted:
                continue

            value = property_item[3]

            if isinstance(value, str) and value.strip():
                return value.strip()

    return ""


def extract_rdap_registrar(
    data: dict[str, Any],
) -> str:
    """
    Extract the registrar from RDAP entities.
    """

    entities = data.get(
        "entities",
        [],
    )

    if not isinstance(entities, list):
        return ""

    def find_registrar(
        items: list[Any],
    ) -> str:
        for item in items:
            if not isinstance(item, dict):
                continue

            roles = item.get(
                "roles",
                [],
            )

            if (
                isinstance(roles, list)
                and "registrar" in [
                    str(role).lower()
                    for role in roles
                ]
            ):
                name = extract_vcard_organization(item)

                if name:
                    return name

                public_ids = item.get(
                    "publicIds",
                    [],
                )

                if isinstance(public_ids, list):
                    for public_id in public_ids:
                        if not isinstance(public_id, dict):
                            continue

                        value = public_id.get(
                            "identifier"
                        )

                        if value:
                            return str(value)

                handle = item.get(
                    "handle"
                )

                if handle:
                    return str(handle)

            nested = item.get(
                "entities",
                [],
            )

            if isinstance(nested, list):
                found = find_registrar(nested)

                if found:
                    return found

        return ""

    return find_registrar(entities)


def extract_rdap_nameservers(
    data: dict[str, Any],
) -> list[str]:
    """
    Extract nameservers from RDAP domain objects.
    """

    nameservers: list[str] = []

    items = data.get(
        "nameservers",
        [],
    )

    if not isinstance(items, list):
        return nameservers

    for item in items:
        if not isinstance(item, dict):
            continue

        name = item.get(
            "ldhName"
        ) or item.get(
            "unicodeName"
        )

        if not isinstance(name, str):
            continue

        name = normalize_nameserver(name)

        if DOMAIN_RE.fullmatch(name):
            nameservers.append(name)

    return sorted(set(nameservers))


def rdap_lookup(
    domain: str,
) -> tuple[str, list[str]]:
    """
    Query the discovered RDAP service for a domain.
    """

    servers = discover_rdap_servers(domain)

    if not servers:
        return "", []

    registrar = ""
    nameservers: list[str] = []

    for server in servers:
        url = (
            server.rstrip("/")
            + "/domain/"
            + urllib.parse.quote(domain, safe="")
        )

        log(
            f"    [RDAP] Querying {url}"
        )

        data = fetch_json(
            url,
            timeout=RDAP_TIMEOUT,
            throttle=True,
        )

        if not isinstance(data, dict):
            continue

        rdap_registrar = extract_rdap_registrar(
            data
        )

        rdap_nameservers = extract_rdap_nameservers(
            data
        )

        registrar, nameservers = merge_registration_data(
            registrar,
            nameservers,
            rdap_registrar,
            rdap_nameservers,
        )

        if registrar and nameservers:
            break

    return registrar, nameservers


# ============================================================
# THREE-STAGE REGISTRATION LOOKUP
# ============================================================

def whois_lookup(
    domain: str,
) -> tuple[str, list[str]]:
    """
    Registration lookup workflow:

        1. Standard WHOIS
        2. IANA-discovered WHOIS
        3. RDAP fallback

    Cache successful results by registrable domain.
    """

    original_domain = normalize_domain(domain)

    lookup_domain = get_whois_domain(
        original_domain
    )

    # --------------------------------------------------------
    # Cache
    # --------------------------------------------------------

    cached = WHOIS_CACHE.get(
        lookup_domain
    )

    if cached is not None:
        log(
            f"    [WHOIS CACHE] "
            f"{original_domain} -> {lookup_domain}"
        )

        registrar, nameservers = cached

        return registrar, nameservers.copy()

    if original_domain != lookup_domain:
        log(
            f"    [REGISTRABLE DOMAIN] "
            f"{original_domain} -> {lookup_domain}"
        )

    registrar = ""
    nameservers: list[str] = []

    # --------------------------------------------------------
    # Stage 1: Standard WHOIS
    # --------------------------------------------------------

    log(
        f"    [WHOIS 1/3] Standard WHOIS: {lookup_domain}"
    )

    result = run_command(
        [
            WHOIS_PATH,
            lookup_domain,
        ],
        timeout=WHOIS_TIMEOUT,
        throttle=True,
    )

    if result.stdout.strip():
        registrar, nameservers = parse_whois(
            result.stdout
        )

    log(
        f"        Registrar: {registrar or '<missing>'}"
    )

    log(
        f"        Nameservers: {len(nameservers)}"
    )

    # --------------------------------------------------------
    # Stage 2: IANA WHOIS discovery
    # --------------------------------------------------------

    if not registrar or not nameservers:
        log(
            "    [WHOIS 2/3] "
            "Discovering registry WHOIS server..."
        )

        server = discover_whois_server(
            lookup_domain
        )

        if server:
            result = run_command(
                [
                    WHOIS_PATH,
                    "-h",
                    server,
                    lookup_domain,
                ],
                timeout=WHOIS_TIMEOUT,
                throttle=True,
            )

            if result.stdout.strip():
                new_registrar, new_nameservers = parse_whois(
                    result.stdout
                )

                registrar, nameservers = merge_registration_data(
                    registrar,
                    nameservers,
                    new_registrar,
                    new_nameservers,
                )

            log(
                f"        Registrar: "
                f"{registrar or '<missing>'}"
            )

            log(
                f"        Nameservers: {len(nameservers)}"
            )

    # --------------------------------------------------------
    # Stage 3: RDAP fallback
    # --------------------------------------------------------

    if not registrar or not nameservers:
        log(
            "    [RDAP 3/3] Attempting RDAP fallback..."
        )

        rdap_registrar, rdap_nameservers = rdap_lookup(
            lookup_domain
        )

        registrar, nameservers = merge_registration_data(
            registrar,
            nameservers,
            rdap_registrar,
            rdap_nameservers,
        )

        log(
            f"        Registrar: "
            f"{registrar or '<missing>'}"
        )

        log(
            f"        Nameservers: {len(nameservers)}"
        )

    # --------------------------------------------------------
    # Cache successful registration data
    # --------------------------------------------------------

    if registrar or nameservers:
        WHOIS_CACHE[lookup_domain] = (
            registrar,
            nameservers.copy(),
        )

    if not registrar and not nameservers:
        log(
            f"    [!] No registration information "
            f"found for {lookup_domain}"
        )

    return registrar, nameservers


# ============================================================
# ORIGINAL DOMAIN
# ============================================================

def get_original_domain(
    domain: str,
) -> DomainRecord:

    log(
        f"[*] Looking up original domain: {domain}"
    )

    registrar, nameservers = whois_lookup(
        domain
    )

    record = DomainRecord(
        domain=domain
    )

    record.add_type(
        "Original"
    )

    record.sources.add(
        "original"
    )

    record.registrar = registrar

    record.add_nameservers(
        nameservers
    )

    return record


# ============================================================
# DNSTWIST
# ============================================================

def run_dnstwist(
    domain: str,
) -> dict[str, DomainRecord]:

    log(
        f"[*] Running DNSTwist against {domain}..."
    )

    result = run_command(
        [
            DNSTWIST_PATH,
            "--registered",
            "--format",
            "json",
            domain,
        ],
        timeout=DNSTWIST_TIMEOUT,
        throttle=False,
    )

    if result.returncode != 0:
        log(
            f"[!] DNSTwist exited with "
            f"code {result.returncode}"
        )

        if result.stderr.strip():
            log(result.stderr.strip())

    data = parse_json_output(
        result.stdout,
        "DNSTwist",
    )

    records: dict[str, DomainRecord] = {}

    if data is None:
        return records

    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        log("[!] Unexpected DNSTwist JSON structure.")
        return records

    for item in data:
        if not isinstance(item, dict):
            continue

        candidate = item.get(
            "domain"
        )

        if not isinstance(candidate, str):
            continue

        candidate = normalize_domain(
            candidate
        )

        if not DOMAIN_RE.fullmatch(candidate):
            continue

        if candidate == domain:
            continue

        fuzzer = item.get(
            "fuzzer",
            "Unknown",
        )

        record = records.setdefault(
            candidate,
            DomainRecord(
                domain=candidate
            ),
        )

        record.add_type(
            str(fuzzer)
        )

        record.sources.add(
            "dnstwist"
        )

    log(
        f"[*] DNSTwist identified "
        f"{len(records)} registered candidate(s)."
    )

    return records


# ============================================================
# URLCRAZY
# ============================================================

def value_is_resolved(value: Any) -> bool:
    if value is None or value is False:
        return False

    if isinstance(value, str):
        return bool(value.strip())

    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0

    return bool(value)


def run_urlcrazy(
    domain: str,
) -> dict[str, DomainRecord]:

    log(
        f"[*] Running URLCrazy against {domain}..."
    )

    result = run_command(
        [
            URLCRAZY_PATH,
            "-f",
            "JSON",
            domain,
        ],
        timeout=URLCRAZY_TIMEOUT,
        throttle=False,
    )

    if result.returncode != 0:
        log(
            f"[!] URLCrazy exited with "
            f"code {result.returncode}"
        )

        if result.stderr.strip():
            log(result.stderr.strip())

    data = parse_json_output(
        result.stdout,
        "URLCrazy",
    )

    records: dict[str, DomainRecord] = {}

    if not isinstance(data, dict):
        log("[!] Unexpected URLCrazy JSON structure.")
        return records

    typos = data.get(
        "typos",
        [],
    )

    if not isinstance(typos, list):
        log("[!] URLCrazy 'typos' is not an array.")
        return records

    for typo in typos:
        if not isinstance(typo, dict):
            continue

        candidate = typo.get(
            "name"
        )

        if not isinstance(candidate, str):
            continue

        candidate = normalize_domain(
            candidate
        )

        if not DOMAIN_RE.fullmatch(candidate):
            continue

        if candidate == domain:
            continue

        has_ns = value_is_resolved(
            typo.get("resolved_ns")
        )

        has_mx = value_is_resolved(
            typo.get("resolved_mx")
        )

        if not (has_ns or has_mx):
            continue

        record = records.setdefault(
            candidate,
            DomainRecord(
                domain=candidate
            ),
        )

        record.add_type(
            str(
                typo.get("type", "Unknown")
            )
        )

        record.sources.add(
            "urlcrazy"
        )

    log(
        f"[*] URLCrazy generated "
        f"{len(typos)} candidate(s)."
    )

    log(
        f"[*] URLCrazy identified "
        f"{len(records)} unique candidate(s) "
        f"with NS and/or MX resolution."
    )

    return records


# ============================================================
# MERGE CANDIDATES
# ============================================================

def merge_candidates(
    destination: dict[str, DomainRecord],
    source: dict[str, DomainRecord],
) -> None:

    for domain, incoming in source.items():
        record = destination.setdefault(
            domain,
            DomainRecord(
                domain=domain
            ),
        )

        for typo_type in incoming.typo_types:
            record.add_type(
                typo_type
            )

        record.sources.update(
            incoming.sources
        )


# ============================================================
# REGISTRATION ENRICHMENT
# ============================================================

def enrich_candidates_with_whois(
    records: dict[str, DomainRecord],
) -> None:

    domains = sorted(records)

    total = len(domains)

    log(
        f"[*] Performing registration lookups "
        f"for {total} unique candidate(s)..."
    )

    for index, domain in enumerate(
        domains,
        start=1,
    ):
        record = records[domain]

        sources = ", ".join(
            sorted(record.sources)
        )

        log(
            f"[*] [{index}/{total}] "
            f"{domain} [{sources}]"
        )

        registrar, nameservers = whois_lookup(
            domain
        )

        record.registrar = registrar

        record.add_nameservers(
            nameservers
        )


# ============================================================
# CSV OUTPUT
# ============================================================

def write_csv(
    filename: Path,
    original: DomainRecord,
    candidates: dict[str, DomainRecord],
) -> None:

    with filename.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.writer(
            handle,
            quoting=csv.QUOTE_MINIMAL,
        )

        writer.writerow([
            "Typo-Type",
            "Domain",
            "Registrar",
            "Name-Servers",
        ])

        writer.writerow([
            "*Original",
            original.domain,
            original.registrar,
            ", ".join(
                sorted(original.nameservers)
            ),
        ])

        for domain in sorted(candidates):
            record = candidates[domain]

            writer.writerow([
                "; ".join(record.typo_types),
                record.domain,
                record.registrar,
                ", ".join(
                    sorted(record.nameservers)
                ),
            ])


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Find typo domains with DNSTwist and URLCrazy, "
            "retrieve registration data using WHOIS and RDAP, "
            "and export results to CSV."
        )
    )

    parser.add_argument(
        "domain",
        help="Domain to scan, e.g. example.com",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output CSV filename",
    )

    parser.add_argument(
        "--lookup-delay",
        type=float,
        default=DEFAULT_LOOKUP_DELAY,
        help=(
            "Minimum interval in seconds between outbound "
            "registration lookup requests. Default: 2.0"
        ),
    )

    parser.add_argument(
        "--lookup-jitter",
        type=float,
        default=DEFAULT_LOOKUP_JITTER,
        help=(
            "Maximum additional randomized delay in seconds. "
            "Default: 0.0"
        ),
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Validate input
    # --------------------------------------------------------

    domain = normalize_domain(
        args.domain
    )

    if not DOMAIN_RE.fullmatch(domain):
        log(
            f"[!] Invalid domain: {args.domain}"
        )
        return 2

    if (
        not 0 <= args.lookup_delay <= 3600
        or not 0 <= args.lookup_jitter <= 3600
    ):
        log(
            "[!] Lookup delay and jitter must be "
            "between 0 and 3600 seconds."
        )
        return 2

    # --------------------------------------------------------
    # Configure throttling
    # --------------------------------------------------------

    LOOKUP_THROTTLE.delay = args.lookup_delay
    LOOKUP_THROTTLE.jitter = args.lookup_jitter
    LOOKUP_THROTTLE.last_request = None

    log(
        f"[*] Lookup delay: "
        f"{LOOKUP_THROTTLE.delay:.2f}s"
    )

    log(
        f"[*] Lookup jitter: "
        f"0-{LOOKUP_THROTTLE.jitter:.2f}s"
    )

    # --------------------------------------------------------
    # Validate tools
    # --------------------------------------------------------

    valid = True

    for name, path in [
        ("DNSTwist", DNSTWIST_PATH),
        ("URLCrazy", URLCRAZY_PATH),
        ("WHOIS", WHOIS_PATH),
    ]:
        if not validate_tool_path(name, path):
            valid = False

    if not valid:
        return 2

    # --------------------------------------------------------
    # Output filename
    # --------------------------------------------------------

    output_file = (
        args.output
        if args.output
        else Path(f"{domain}-typos.csv")
    )

    # --------------------------------------------------------
    # Original domain
    # --------------------------------------------------------

    original = get_original_domain(
        domain
    )

    log(
        f"[*] Original registrar: "
        f"{original.registrar or '<not found>'}"
    )

    log(
        f"[*] Original nameservers: "
        f"{', '.join(original.nameservers) or '<not found>'}"
    )

    # --------------------------------------------------------
    # DNSTwist
    # --------------------------------------------------------

    dnstwist_records = run_dnstwist(
        domain
    )

    # --------------------------------------------------------
    # URLCrazy
    # --------------------------------------------------------

    urlcrazy_records = run_urlcrazy(
        domain
    )

    # --------------------------------------------------------
    # Merge results
    # --------------------------------------------------------

    candidates: dict[str, DomainRecord] = {}

    merge_candidates(
        candidates,
        dnstwist_records,
    )

    merge_candidates(
        candidates,
        urlcrazy_records,
    )

    candidates.pop(
        domain,
        None,
    )

    log(
        f"[*] {len(candidates)} unique candidate(s) "
        f"qualify for registration lookups."
    )

    # --------------------------------------------------------
    # WHOIS + RDAP enrichment
    # --------------------------------------------------------

    enrich_candidates_with_whois(
        candidates
    )

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    write_csv(
        output_file,
        original,
        candidates,
    )

    log(
        f"[+] Wrote {len(candidates) + 1} "
        f"record(s) to {output_file}"
    )

    log(
        f"[*] Registration cache: "
        f"{len(WHOIS_CACHE)} domain(s)"
    )

    log(
        f"[*] WHOIS server cache: "
        f"{len(WHOIS_SERVER_CACHE)} TLD(s)"
    )

    log(
        f"[*] RDAP server cache: "
        f"{len(RDAP_SERVER_CACHE)} TLD(s)"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

