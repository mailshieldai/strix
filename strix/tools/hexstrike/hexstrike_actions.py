"""
HexStrike AI Security Testing Actions

Provides Strix tool wrappers for HexStrike AI security testing capabilities.
Includes 150+ security tools for penetration testing, bug bounty, CTF challenges,
and security research.
"""

from typing import Any

from strix.tools.registry import register_tool


# =============================================================================
# Network Scanning Tools
# =============================================================================


@register_tool
def hexstrike_nmap_scan(
    target: str,
    scan_type: str = "-sV",
    ports: str = "",
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute an enhanced Nmap scan against a target.

    Performs comprehensive port scanning with service version detection,
    OS fingerprinting, and vulnerability scanning.

    Args:
        target: IP address, hostname, or CIDR range to scan
        scan_type: Nmap scan type (e.g., -sV for version, -sC for scripts, -sS for SYN)
        ports: Comma-separated ports or ranges (e.g., "22,80,443" or "1-1000")
        additional_args: Additional Nmap arguments (e.g., "-O -T4 --script vuln")

    Returns:
        Scan results with open ports, services, and vulnerabilities
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.nmap_scan(
        target=target,
        scan_type=scan_type,
        ports=ports,
        additional_args=additional_args,
    )


@register_tool
def hexstrike_gobuster_scan(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute Gobuster to discover directories, subdomains, or virtual hosts.

    Fast directory and subdomain brute-forcer for web applications.

    Args:
        url: Target URL (e.g., "https://example.com")
        mode: Scan mode - "dir" (directories), "dns" (subdomains), "vhost" (virtual hosts), "fuzz"
        wordlist: Path to wordlist file for brute-forcing
        additional_args: Additional Gobuster arguments (e.g., "-x php,txt -t 50")

    Returns:
        Discovered paths, subdomains, or virtual hosts
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.gobuster_scan(
        url=url,
        mode=mode,
        wordlist=wordlist,
        additional_args=additional_args,
    )


@register_tool
def hexstrike_nuclei_scan(
    target: str,
    severity: str = "",
    tags: str = "",
    template: str = "",
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute Nuclei vulnerability scanner for comprehensive security testing.

    Fast and customizable vulnerability scanner with 10,000+ templates
    covering CVEs, misconfigurations, exposures, and more.

    Args:
        target: Target URL or IP to scan
        severity: Filter by severity (critical, high, medium, low, info) - comma-separated
        tags: Filter by tags (e.g., "cve,rce,lfi,xss,sqli")
        template: Path to custom template or template directory
        additional_args: Additional Nuclei arguments (e.g., "-rate-limit 100")

    Returns:
        Discovered vulnerabilities with severity, references, and remediation
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.nuclei_scan(
        target=target,
        severity=severity,
        tags=tags,
        template=template,
        additional_args=additional_args,
    )


@register_tool
def hexstrike_sqlmap_scan(
    url: str,
    data: str = "",
    cookie: str = "",
    level: int = 1,
    risk: int = 1,
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute SQLMap for automatic SQL injection detection and exploitation.

    Comprehensive SQL injection testing tool that can detect and exploit
    SQL injection vulnerabilities across various database types.

    Args:
        url: Target URL with injection point (use * to mark injection point)
        data: POST data (e.g., "username=admin&password=*")
        cookie: HTTP cookies to include
        level: Test thoroughness 1-5 (higher = more tests, slower)
        risk: Risk level 1-3 (higher = more dangerous payloads)
        additional_args: Additional SQLMap arguments (e.g., "--dbs --dump")

    Returns:
        SQL injection vulnerabilities, database info, and extracted data
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.sqlmap_scan(
        url=url,
        data=data,
        cookie=cookie,
        level=level,
        risk=risk,
        additional_args=additional_args,
    )


@register_tool
def hexstrike_ffuf_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute FFUF (Fuzz Faster U Fool) for web fuzzing.

    Fast web fuzzer for discovering hidden endpoints, parameters,
    and subdomain enumeration.

    Args:
        url: Target URL with FUZZ placeholder (e.g., "https://example.com/FUZZ")
        wordlist: Path to wordlist for fuzzing
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        additional_args: Additional FFUF arguments (e.g., "-fc 404 -t 100")

    Returns:
        Discovered endpoints with response codes and sizes
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.ffuf_scan(
        url=url,
        wordlist=wordlist,
        method=method,
        additional_args=additional_args,
    )


# =============================================================================
# Subdomain Enumeration Tools
# =============================================================================


@register_tool
def hexstrike_amass_enum(
    domain: str,
    passive: bool = True,
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute Amass for comprehensive subdomain enumeration.

    Advanced subdomain discovery through OSINT, DNS brute-forcing,
    certificate transparency, and web archives.

    Args:
        domain: Target domain to enumerate (e.g., "example.com")
        passive: Use passive enumeration only (no DNS resolution)
        additional_args: Additional Amass arguments (e.g., "-brute -w wordlist.txt")

    Returns:
        Discovered subdomains with resolution info and sources
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.amass_enum(
        domain=domain,
        passive=passive,
        additional_args=additional_args,
    )


@register_tool
def hexstrike_subfinder_scan(
    domain: str,
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute Subfinder for fast passive subdomain discovery.

    Lightning-fast subdomain enumeration using multiple online sources
    including certificate transparency, DNS datasets, and search engines.

    Args:
        domain: Target domain to enumerate (e.g., "example.com")
        additional_args: Additional Subfinder arguments (e.g., "-all -silent")

    Returns:
        List of discovered subdomains from multiple sources
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.subfinder_scan(
        domain=domain,
        additional_args=additional_args,
    )


# =============================================================================
# Web Application Security Tools
# =============================================================================


@register_tool
def hexstrike_nikto_scan(
    target: str,
    port: int = 80,
    ssl: bool = False,
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute Nikto web server vulnerability scanner.

    Comprehensive web server scanner that checks for dangerous files,
    outdated software, server misconfigurations, and security issues.

    Args:
        target: Target hostname or IP address
        port: Target port (default: 80)
        ssl: Enable SSL/TLS (use for HTTPS targets)
        additional_args: Additional Nikto arguments (e.g., "-Tuning 123")

    Returns:
        Web server vulnerabilities, misconfigurations, and security issues
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.nikto_scan(
        target=target,
        port=port,
        ssl=ssl,
        additional_args=additional_args,
    )


@register_tool
def hexstrike_wpscan_scan(
    url: str,
    enumerate: str = "vp,vt,u",
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute WPScan for WordPress vulnerability scanning.

    Comprehensive WordPress security scanner that identifies vulnerable
    plugins, themes, users, and WordPress core issues.

    Args:
        url: WordPress site URL (e.g., "https://example.com/")
        enumerate: What to enumerate - vp (plugins), vt (themes), u (users), ap (all plugins)
        additional_args: Additional WPScan arguments (e.g., "--api-token TOKEN")

    Returns:
        WordPress vulnerabilities, exposed users, outdated components
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.wpscan_scan(
        url=url,
        enumerate=enumerate,
        additional_args=additional_args,
    )


# =============================================================================
# Password Attack Tools
# =============================================================================


@register_tool
def hexstrike_hydra_attack(
    target: str,
    service: str,
    username: str = "",
    username_file: str = "",
    password_file: str = "/usr/share/wordlists/rockyou.txt",
    additional_args: str = "",
) -> dict[str, Any]:
    """
    Execute Hydra for password brute-force attacks.

    Fast and flexible network authentication cracker supporting
    50+ protocols including SSH, FTP, HTTP, SMB, and more.

    Args:
        target: Target hostname or IP address
        service: Service to attack (ssh, ftp, http-get, http-post, smb, mysql, etc.)
        username: Single username to test
        username_file: Path to file containing usernames (one per line)
        password_file: Path to password wordlist
        additional_args: Additional Hydra arguments (e.g., "-t 4 -V")

    Returns:
        Valid credentials found during brute-force attack
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.hydra_attack(
        target=target,
        service=service,
        username=username,
        username_file=username_file,
        password_file=password_file,
        additional_args=additional_args,
    )


# =============================================================================
# Generic Tool Execution
# =============================================================================


@register_tool
def hexstrike_execute_tool(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Execute any HexStrike security tool by name.

    Generic interface to access all 150+ HexStrike security tools
    including those not directly wrapped by other functions.

    Args:
        tool_name: Name of the HexStrike tool to execute
        arguments: Dictionary of tool-specific arguments

    Returns:
        Tool execution results

    Available tools include:
    - Network: nmap, masscan, rustscan, autorecon
    - Web: gobuster, feroxbuster, ffuf, dirb, dirsearch
    - Vuln: nuclei, nikto, sqlmap, dalfox, xsstrike
    - Recon: amass, subfinder, fierce, dnsenum, theharvester
    - Cloud: prowler, scout-suite, trivy, kube-hunter
    - Password: hydra, john, hashcat, medusa
    - Binary: gdb, radare2, binwalk, ghidra
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.execute_tool(
        tool_name=tool_name,
        arguments=arguments or {},
    )


@register_tool
def hexstrike_list_tools() -> dict[str, Any]:
    """
    List all available HexStrike security tools.

    Returns comprehensive list of 150+ security tools available
    through HexStrike, organized by category.

    Returns:
        Dictionary of available tools organized by category
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.list_tools()


# =============================================================================
# Intelligence & Analysis
# =============================================================================


@register_tool
def hexstrike_analyze_target(
    target: str,
    analysis_type: str = "comprehensive",
) -> dict[str, Any]:
    """
    Analyze a target using HexStrike's AI-powered intelligence engine.

    Performs comprehensive target analysis including technology detection,
    attack surface mapping, vulnerability prioritization, and recommended
    testing strategies.

    Args:
        target: Target URL, domain, or IP address to analyze
        analysis_type: Type of analysis - "comprehensive", "quick", "deep"

    Returns:
        Target profile with technologies, attack surface, and recommendations
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.analyze_target(
        target=target,
        analysis_type=analysis_type,
    )


@register_tool
def hexstrike_server_status() -> dict[str, Any]:
    """
    Check HexStrike server status and health.

    Verifies connectivity to HexStrike server and returns
    server version, available tools, and system status.

    Returns:
        Server health status, version, and capabilities
    """
    from .hexstrike_client import get_hexstrike_client

    client = get_hexstrike_client()
    return client.get_status()
