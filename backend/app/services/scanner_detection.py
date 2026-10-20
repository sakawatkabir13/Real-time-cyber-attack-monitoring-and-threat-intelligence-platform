"""Shared reconnaissance indicators and conservative completed-window evidence."""

import re
from urllib.parse import urlsplit


SCANNER_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|metasploit|nessus|openvas|"
    r"w3af|acunetix|ibm\s*appscan|dirbuster|gobuster|ffuf|fuzz\s+faster\s+u\s+fool|"
    r"wfuzz|nuclei|whatweb|shodan|zgrab|censys|feroxbuster)", re.I,
)
SCANNER_PATH_RE = re.compile(
    r"(\.env$|\.git/config|\.htaccess|\.htpasswd|web\.config|"
    r"phpinfo\.php|php-info\.php|info\.php|"
    r"wp-admin|wp-login\.php|wp-config\.php|xmlrpc\.php|"
    r"phpmyadmin|/pma/|/admin/|/manager/html|"
    r"/shell\.|/cmd\.|/backdoor\.|/c99\.|/r57\.|"
    r"\.(bak|old|backup|sql|dump|tar\.gz|zip)(?:\?|$))", re.I,
)


def scanner_indicator(path: str, user_agent: str) -> bool:
    # Query strings do not turn an ordinary filename into a sensitive target.
    return bool(SCANNER_UA_RE.search(user_agent or "") or
                SCANNER_PATH_RE.search(urlsplit(path or "/").path))


def is_directory_enumeration(
    *, request_count: int, unique_paths: float, top_path_share: float,
    request_rate: float, peak_second_requests: float,
) -> bool:
    """Flag fast, broad path probing, including sites that rewrite misses to HTTP 200."""
    return (
        request_count >= 120
        and unique_paths >= 80
        and unique_paths / request_count >= 0.7
        and top_path_share <= 0.1
        and (request_rate >= 2.0 or peak_second_requests >= 10)
    )
