#!/usr/bin/env python3

import os
import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Tool paths
#
# Hardcode these if dnstwist/urlcrazy are not in $PATH.
#
# Examples:
#
# DNSTWIST_PATH = "/opt/dnstwist/dnstwist.py"
# URLCRAZY_PATH = "/opt/urlcrazy/urlcrazy"
# WHOIS_PATH = "/usr/bin/whois"
#
# If the commands are already in $PATH, simply use their command names:
# ---------------------------------------------------------------------------

DNSTWIST_PATH = "/usr/bin/dnstwist"
URLCRAZY_PATH = "/opt/urlcrazy/urlcrazy"
WHOIS_PATH = "/usr/bin/whois"


# ---------------------------------------------------------------------------
# Configuration / Regex
# ---------------------------------------------------------------------------

DOMAIN_RE = re.compile(
    r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)

WHOIS_REGISTRAR_PATTERNS = [
    re.compile(r"(?im)^\s*Registrar:\s*(.+?)\s*$"),
    re.compile(r"(?im)^\s*Registrar Name:\s*(.+?)\s*$"),
    re.compile(r"(?im)^\s*Sponsoring Registrar:\s*(.+?)\s*$"),
]

WHOIS_NS_PATTERNS = [
    re.compile(r"(?im)^\s*Name Server:\s*(\S+)\s*$"),
    re.compile(r"(?im)^\s*Name Servers?:\s*(\S+)\s*$"),
    re.compile(r"(?im)^\s*Nserver:\s*(\S+)(?:\s+.*)?$"),
    re.compile(r"(?im)^\s*Nameserver:\s*(\S+)(?:\s+.*)?$"),
]


# ---------------------------------------------------------------------------
# Domain record
# ---------------------------------------------------------------------------

@dataclass
class DomainRecord:
    domain: str
    typo_types: list[str] = field(default_factory=list)
    registrar: str = ""
    nameservers: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)

    def add_type(self, typo_type: str) -> None:
        typo_type = normalize_typo_type(typo_type)

        if typo_type and typo_type not in self.typo_types:
            self.typo_types.append(typo_type)

    def add_nameservers(self, nameservers: list[str]) -> None:
        existing = {ns.lower() for ns in self.nameservers}

        for ns in nameservers:
            ns = normalize_nameserver(ns)

            if ns and ns.lower() not in existing:
                self.nameservers.append(ns)
                existing.add(ns.lower())


# ---------------------------------------------------------------------------
# Validate Tool Paths
# ---------------------------------------------------------------------------

def validate_tool_path(
    name: str,
    path: str,
) -> bool:
    """
    Validate a configured external tool.

    Supports either:
        /absolute/path/to/tool

    or:
        tool-name

    If an absolute/relative filesystem path is provided, verify that it
    exists and is executable.

    Otherwise, search for it in $PATH.
    """

    # A path containing "/" is treated as an explicit filesystem path.
    if "/" in path:
        tool_path = Path(path)

        if not tool_path.exists():
            print(
                f"[!] {name} does not exist: {path}",
                file=sys.stderr,
            )
            return False

        if not tool_path.is_file():
            print(
                f"[!] {name} is not a file: {path}",
                file=sys.stderr,
            )
            return False

        if not os.access(tool_path, os.X_OK):
            print(
                f"[!] {name} is not executable: {path}",
                file=sys.stderr,
            )
            return False

        return True

    # Otherwise resolve it through $PATH.
    resolved = shutil.which(path)

    if resolved is None:
        print(
            f"[!] {name} was not found in $PATH: {path}",
            file=sys.stderr,
        )
        return False

    return True


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------

def normalize_domain(domain: str) -> str:
    """
    Normalize a user-supplied domain.

    Allows:
        example.com
        https://example.com
        http://example.com/foo

    Returns:
        example.com
    """

    domain = domain.strip().lower()

    domain = re.sub(
        r"^[a-z][a-z0-9+.-]*://",
        "",
        domain,
        flags=re.IGNORECASE,
    )

    domain = domain.split("/", 1)[0]

    # Basic handling for host:port input.
    if ":" in domain:
        domain = domain.split(":", 1)[0]

    return domain.rstrip(".")


def normalize_nameserver(ns: str) -> str:
    """
    Normalize nameserver names for consistent CSV output.
    """

    ns = ns.strip().strip(".,;")

    return ns.lower().rstrip(".")


def normalize_typo_type(value: str) -> str:
    """
    Convert tool-specific mutation names into a readable form.

    Examples:
        vowel-swap     -> Vowel Swap
        bitsquatting   -> Bitsquatting
        insertion      -> Insertion
    """

    value = str(value).strip()

    if not value:
        return "Unknown"

    value = value.replace("_", " ")
    value = value.replace("-", " ")

    value = re.sub(
        r"\s+",
        " ",
        value,
    )

    return value.title()


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(
    command: list[str],
    timeout: int = 3600,
) -> subprocess.CompletedProcess:

    try:
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )

    except subprocess.TimeoutExpired:

        print(
            f"[!] Command timed out: {' '.join(command)}",
            file=sys.stderr,
        )

        return subprocess.CompletedProcess(
            command,
            returncode=124,
            stdout="",
            stderr="Command timed out",
        )

    except OSError as exc:

        print(
            f"[!] Failed to execute {' '.join(command)}: {exc}",
            file=sys.stderr,
        )

        return subprocess.CompletedProcess(
            command,
            returncode=1,
            stdout="",
            stderr=str(exc),
        )


def parse_json_output(
    output: str,
    tool_name: str,
) -> Any:
    """
    Parse JSON emitted by DNSTwist or URLCrazy.

    Handles:
      - Normal JSON output.
      - Warnings or informational messages preceding JSON.
      - Leading whitespace.
      - Trailing non-JSON text.

    Uses JSONDecoder.raw_decode() to extract the first valid JSON
    document, ignoring surrounding tool messages.
    """

    output = output.strip()

    if not output:
        print(
            f"[!] {tool_name} returned no output.",
            file=sys.stderr,
        )
        return None

    # First attempt normal JSON parsing.
    try:
        return json.loads(output)

    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()

    # Find potential JSON document starting positions.
    for match in re.finditer(r"[\{\[]", output):
        position = match.start()

        try:
            data, end_position = decoder.raw_decode(
                output[position:]
            )

            if position > 0:
                print(
                    f"[!] {tool_name}: Ignored non-JSON "
                    f"output preceding JSON.",
                    file=sys.stderr,
                )

                print(
                    f"    {output[:position].strip()}",
                    file=sys.stderr,
                )

            trailing = output[position + end_position:].strip()

            if trailing:
                print(
                    f"[!] {tool_name}: Ignored trailing "
                    f"non-JSON output.",
                    file=sys.stderr,
                )

            return data

        except json.JSONDecodeError:
            continue

    print(
        f"[!] Unable to locate valid JSON in "
        f"{tool_name} output.",
        file=sys.stderr,
    )

    print(
        f"[!] First 500 bytes:\n{output[:500]}",
        file=sys.stderr,
    )

    return None


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def parse_whois(
    output: str,
) -> tuple[str, list[str]]:
    """
    Extract registrar and nameservers from WHOIS output.

    WHOIS is unfortunately not completely standardized between registries,
    so several common field representations are supported.
    """

    registrar = ""
    nameservers: list[str] = []

    # ------------------------------------------------------------------
    # Registrar
    # ------------------------------------------------------------------

    for pattern in WHOIS_REGISTRAR_PATTERNS:

        match = pattern.search(output)

        if match:
            candidate = match.group(1).strip()

            if candidate:
                registrar = candidate
                break

    # ------------------------------------------------------------------
    # Nameservers
    # ------------------------------------------------------------------

    for pattern in WHOIS_NS_PATTERNS:

        for match in pattern.finditer(output):

            ns = normalize_nameserver(
                match.group(1)
            )

            if DOMAIN_RE.fullmatch(ns):
                nameservers.append(ns)

    # Deduplicate while maintaining stable output.
    nameservers = sorted(
        set(nameservers)
    )

    return registrar, nameservers


def whois_lookup(
    domain: str,
) -> tuple[str, list[str]]:
    """
    Perform a WHOIS lookup and return:

        (registrar, [nameservers])
    """

    print(
        f"    [WHOIS] {domain}",
        file=sys.stderr,
    )

    result = run_command(
        [
            WHOIS_PATH,
            domain,
        ],
        timeout=60,
    )

    # Some WHOIS clients return non-zero status while still providing
    # useful output, so parse stdout whenever it exists.

    if not result.stdout.strip():

        print(
            f"    [!] WHOIS returned no data for {domain}",
            file=sys.stderr,
        )

        if result.stderr.strip():
            print(
                f"        {result.stderr.strip()}",
                file=sys.stderr,
            )

        return "", []

    registrar, nameservers = parse_whois(
        result.stdout
    )

    return registrar, nameservers


# ---------------------------------------------------------------------------
# Original domain
# ---------------------------------------------------------------------------

def get_original_domain(
    domain: str,
) -> DomainRecord:
    """
    WHOIS the original domain before running typo-generation tools.
    """

    print(
        f"[*] Looking up original domain: {domain}",
        file=sys.stderr,
    )

    registrar, nameservers = whois_lookup(
        domain
    )

    record = DomainRecord(
        domain=domain,
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


# ---------------------------------------------------------------------------
# DNSTwist
# ---------------------------------------------------------------------------

def run_dnstwist(
    domain: str,
) -> dict[str, DomainRecord]:
    """
    Execute:

        dnstwist -a --registered --format json DOMAIN

    Because --registered is being used, domains returned by DNSTwist
    are considered candidates for WHOIS.
    
    Note: Consider adding --nameservers 1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4

    DNSTwist JSON looks like:

        {
            "dns_a": [...],
            "dns_mx": [...],
            "dns_ns": [...],
            "domain": "examplee.com",
            "fuzzer": "insertion"
        }

    or:

        {
            "domain": "examplee.com",
            "fuzzer": "insertion",
            "whois_created": "...",
            "whois_registrar": "..."
        }

    The DNSTwist registrar/NS information is NOT used as authoritative
    CSV metadata. A separate WHOIS lookup is performed later.
    """

    print(
        f"[*] Running DNSTwist against {domain}...",
        file=sys.stderr,
    )

    command = [
        DNSTWIST_PATH,
        "--registered",
        "--format",
        "json",
        domain,
    ]

    result = run_command(
        command,
        timeout=3600,
    )

    if result.returncode != 0:

        print(
            f"[!] DNSTwist returned exit code {result.returncode}.",
            file=sys.stderr,
        )

        if result.stderr.strip():
            print(
                result.stderr.strip(),
                file=sys.stderr,
            )

    data = parse_json_output(
        result.stdout,
        "DNSTwist",
    )

    records: dict[str, DomainRecord] = {}

    if data is None:
        return records

    # Standard DNSTwist JSON is an array.
    #
    # Be tolerant of a single object as well.

    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):

        print(
            "[!] Unexpected DNSTwist JSON structure.",
            file=sys.stderr,
        )

        return records

    for item in data:

        if not isinstance(item, dict):
            continue

        candidate = item.get("domain")

        if not isinstance(candidate, str):
            continue

        candidate = normalize_domain(
            candidate
        )

        if not DOMAIN_RE.fullmatch(candidate):
            continue

        # DNSTwist sometimes includes the original domain.
        # It is handled separately.

        if candidate == domain:
            continue

        fuzzer = item.get(
            "fuzzer",
            "Unknown",
        )

        record = records.setdefault(
            candidate,
            DomainRecord(
                domain=candidate,
            ),
        )

        record.add_type(
            str(fuzzer)
        )

        record.sources.add(
            "dnstwist"
        )

    print(
        f"[*] DNSTwist identified "
        f"{len(records)} registered candidate(s).",
        file=sys.stderr,
    )

    return records


# ---------------------------------------------------------------------------
# URLCrazy
# ---------------------------------------------------------------------------

def value_is_resolved(
    value: Any,
) -> bool:
    """
    Determine whether a URLCrazy resolved_ns/resolved_mx value
    represents a successful resolution.

    Handles:
        None
        false
        ""
        []
        ["ns1.example.com"]
        "ns1.example.com"
    """

    if value is None:
        return False

    if value is False:
        return False

    if isinstance(value, str):
        return bool(value.strip())

    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0

    return bool(value)


def run_urlcrazy(
    domain: str,
) -> dict[str, DomainRecord]:
    """
    Execute:

        urlcrazy -f JSON DOMAIN

    A URLCrazy candidate qualifies for WHOIS when either:

        resolved_ns

    or:

        resolved_mx

    contains data.

    Expected URLCrazy JSON:

        {
            "domain": "example",
            "extension": "com",
            "tld": "...",
            "typos": [
                {
                    "type": "...",
                    "name": "...",
                    "valid_name": true,
                    "resolved_a": [...],
                    "resolved_ns": [...],
                    "resolved_mx": [...]
                }
            ]
        }
    """

    print(
        f"[*] Running URLCrazy against {domain}...",
        file=sys.stderr,
    )

    command = [
        URLCRAZY_PATH,
        "-f",
        "JSON",
        domain,
    ]

    result = run_command(
        command,
        timeout=600,
    )

    if result.returncode != 0:

        print(
            f"[!] URLCrazy returned exit code {result.returncode}.",
            file=sys.stderr,
        )

        if result.stderr.strip():
            print(
                result.stderr.strip(),
                file=sys.stderr,
            )

    data = parse_json_output(
        result.stdout,
        "URLCrazy",
    )

    records: dict[str, DomainRecord] = {}

    if data is None:
        return records

    if not isinstance(data, dict):

        print(
            "[!] Unexpected URLCrazy JSON structure.",
            file=sys.stderr,
        )

        return records

    typos = data.get(
        "typos",
        [],
    )

    if not isinstance(typos, list):

        print(
            "[!] URLCrazy JSON does not contain a valid 'typos' array.",
            file=sys.stderr,
        )

        return records

    total = len(typos)
    resolved = 0

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

        resolved_ns = typo.get(
            "resolved_ns"
        )

        resolved_mx = typo.get(
            "resolved_mx"
        )

        has_ns = value_is_resolved(
            resolved_ns
        )

        has_mx = value_is_resolved(
            resolved_mx
        )

        # Requirement:
        #
        # WHOIS URLCrazy candidates when NS and/or MX resolved.

        if not (has_ns or has_mx):
            continue

        typo_type = typo.get(
            "type",
            "Unknown",
        )

        record = records.setdefault(
            candidate,
            DomainRecord(
                domain=candidate,
            ),
        )

        record.add_type(
            str(typo_type)
        )

        record.sources.add(
            "urlcrazy"
        )

        resolved += 1

    print(
        f"[*] URLCrazy generated {total} candidate(s).",
        file=sys.stderr,
    )

    print(
        f"[*] URLCrazy identified {len(records)} unique candidate(s) "
        f"with NS and/or MX resolution.",
        file=sys.stderr,
    )

    return records


# ---------------------------------------------------------------------------
# Merge candidates
# ---------------------------------------------------------------------------

def merge_candidates(
    destination: dict[str, DomainRecord],
    source: dict[str, DomainRecord],
) -> None:
    """
    Merge DNSTwist and URLCrazy results.

    A domain may be discovered by both tools.
    """

    for domain, incoming in source.items():

        current = destination.setdefault(
            domain,
            DomainRecord(
                domain=domain,
            ),
        )

        for typo_type in incoming.typo_types:
            current.add_type(
                typo_type
            )

        current.sources.update(
            incoming.sources
        )


# ---------------------------------------------------------------------------
# WHOIS typo candidates
# ---------------------------------------------------------------------------

def enrich_candidates_with_whois(
    records: dict[str, DomainRecord],
) -> None:
    """
    WHOIS every candidate selected by DNSTwist/URLCrazy.

    WHOIS is authoritative for:
        Registrar
        Name servers
    """

    domains = sorted(
        records.keys()
    )

    total = len(domains)

    print(
        f"[*] Performing WHOIS against "
        f"{total} unique typo candidate(s)...",
        file=sys.stderr,
    )

    for index, domain in enumerate(
        domains,
        start=1,
    ):

        record = records[domain]

        sources = ", ".join(
            sorted(record.sources)
        )

        print(
            f"[*] [{index}/{total}] {domain} "
            f"[{sources}]",
            file=sys.stderr,
        )

        registrar, nameservers = whois_lookup(
            domain
        )

        record.registrar = registrar

        record.add_nameservers(
            nameservers
        )


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def write_csv(
    filename: Path,
    original: DomainRecord,
    candidates: dict[str, DomainRecord],
) -> None:
    """
    Write:

        Typo-Type,Domain,Registrar,Name-Servers

    Python's CSV writer automatically quotes fields containing commas.

    Therefore:

        Network Solutions, LLC

    becomes:

        "Network Solutions, LLC"

    and:

        ns1.example.com, ns2.example.com

    becomes:

        "ns1.example.com, ns2.example.com"

    This prevents commas inside fields from corrupting the CSV.
    """

    with filename.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file_handle:

        writer = csv.writer(
            file_handle,
            quoting=csv.QUOTE_MINIMAL,
        )

        writer.writerow(
            [
                "Typo-Type",
                "Domain",
                "Registrar",
                "Name-Servers",
            ]
        )

        # ---------------------------------------------------------------
        # Original domain
        # ---------------------------------------------------------------

        writer.writerow(
            [
                "*Original",
                original.domain,
                original.registrar,
                ", ".join(
                    sorted(original.nameservers)
                ),
            ]
        )

        # ---------------------------------------------------------------
        # Typo domains
        # ---------------------------------------------------------------

        for domain in sorted(candidates):

            record = candidates[domain]

            typo_type = "; ".join(
                record.typo_types
            )

            nameservers = ", ".join(
                sorted(record.nameservers)
            )

            writer.writerow(
                [
                    typo_type,
                    record.domain,
                    record.registrar,
                    nameservers,
                ]
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Discover typo domains using DNSTwist and URLCrazy, "
            "WHOIS qualifying candidates, and export registrar and "
            "nameserver information to CSV."
        )
    )

    parser.add_argument(
        "domain",
        help="Domain to analyze, e.g. example.com",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help=(
            "Output CSV file. "
            "Default: <domain>-typos.csv"
        ),
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Validate domain
    # ------------------------------------------------------------------

    domain = normalize_domain(
        args.domain
    )

    if not DOMAIN_RE.fullmatch(domain):

        print(
            f"[!] Invalid domain: {args.domain}",
            file=sys.stderr,
        )

        return 2

    # ------------------------------------------------------------------
    # Dependencies
    # ------------------------------------------------------------------

    tools_valid = True

    if not validate_tool_path(
        "DNSTwist",
        DNSTWIST_PATH,
    ):
        tools_valid = False

    if not validate_tool_path(
        "URLCrazy",
        URLCRAZY_PATH,
    ):
        tools_valid = False

    if not validate_tool_path(
        "WHOIS",
        WHOIS_PATH,
    ):
        tools_valid = False

    if not tools_valid:
        return 2

    # ------------------------------------------------------------------
    # Output filename
    # ------------------------------------------------------------------

    if args.output:
        output_file = args.output
    else:
        output_file = Path(
            f"{domain}-typos.csv"
        )

    # ------------------------------------------------------------------
    # 1. Original WHOIS
    # ------------------------------------------------------------------

    original = get_original_domain(
        domain
    )

    print(
        f"[*] Original registrar: "
        f"{original.registrar or '<not found>'}",
        file=sys.stderr,
    )

    print(
        f"[*] Original nameservers: "
        f"{', '.join(original.nameservers) or '<not found>'}",
        file=sys.stderr,
    )

    # ------------------------------------------------------------------
    # 2. DNSTwist
    # ------------------------------------------------------------------

    dnstwist_records = run_dnstwist(
        domain
    )

    # ------------------------------------------------------------------
    # 3. URLCrazy
    # ------------------------------------------------------------------

    urlcrazy_records = run_urlcrazy(
        domain
    )

    # ------------------------------------------------------------------
    # 4. Merge
    # ------------------------------------------------------------------

    candidates: dict[str, DomainRecord] = {}

    merge_candidates(
        candidates,
        dnstwist_records,
    )

    merge_candidates(
        candidates,
        urlcrazy_records,
    )

    # Defensive removal of original domain.
    candidates.pop(
        domain,
        None,
    )

    print(
        f"[*] {len(candidates)} unique candidate(s) "
        f"qualify for WHOIS.",
        file=sys.stderr,
    )

    # ------------------------------------------------------------------
    # 5. WHOIS every qualifying candidate
    # ------------------------------------------------------------------

    enrich_candidates_with_whois(
        candidates
    )

    # ------------------------------------------------------------------
    # 6. Write CSV
    # ------------------------------------------------------------------

    write_csv(
        output_file,
        original,
        candidates,
    )

    print(
        f"[+] Wrote {len(candidates) + 1} record(s) "
        f"to {output_file}",
        file=sys.stderr,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
