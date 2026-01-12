"""
HexStrike AI Client - HTTP Client for HexStrike Security Server

Provides a thin wrapper around the HexStrike AI server API for use
within Strix agent framework.
"""

import os
import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

# Configuration
DEFAULT_SERVER_URL = os.environ.get("HEXSTRIKE_SERVER_URL", "http://127.0.0.1:8888")
DEFAULT_TIMEOUT = int(os.environ.get("HEXSTRIKE_TIMEOUT", "300"))
MAX_RETRIES = 3


class HexStrikeClient:
    """HTTP client for communicating with HexStrike AI server."""

    _instance: "HexStrikeClient | None" = None

    def __init__(
        self,
        server_url: str = DEFAULT_SERVER_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self._connected = False

    @classmethod
    def get_instance(cls) -> "HexStrikeClient":
        """Get singleton instance of HexStrikeClient."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def check_connection(self) -> dict[str, Any]:
        """Check if HexStrike server is available."""
        try:
            response = self.session.get(
                f"{self.server_url}/health",
                timeout=5,
            )
            response.raise_for_status()
            self._connected = True
            return response.json()
        except requests.exceptions.RequestException as e:
            self._connected = False
            return {
                "success": False,
                "error": f"Connection failed: {e}",
                "status": "offline",
            }

    def _post(self, endpoint: str, data: dict[str, Any]) -> dict[str, Any]:
        """Make a POST request to HexStrike server."""
        url = f"{self.server_url}/{endpoint.lstrip('/')}"

        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.post(
                    url,
                    json=data,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.Timeout:
                if attempt == MAX_RETRIES - 1:
                    return {
                        "success": False,
                        "error": f"Request timed out after {self.timeout}s",
                    }
                logger.warning(f"Request timeout, retrying ({attempt + 1}/{MAX_RETRIES})")
            except requests.exceptions.ConnectionError as e:
                return {
                    "success": False,
                    "error": f"Connection error: {e}. Is HexStrike server running?",
                }
            except requests.exceptions.RequestException as e:
                return {
                    "success": False,
                    "error": f"Request failed: {e}",
                }

        return {"success": False, "error": "Max retries exceeded"}

    def _get(self, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Make a GET request to HexStrike server."""
        url = f"{self.server_url}/{endpoint.lstrip('/')}"

        try:
            response = self.session.get(
                url,
                params=params or {},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"Request failed: {e}",
            }

    # ==========================================================================
    # Network Scanning Tools
    # ==========================================================================

    def nmap_scan(
        self,
        target: str,
        scan_type: str = "-sV",
        ports: str = "",
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute Nmap scan against target."""
        return self._post(
            "api/tools/nmap",
            {
                "target": target,
                "scan_type": scan_type,
                "ports": ports,
                "additional_args": additional_args,
                "use_recovery": True,
            },
        )

    def gobuster_scan(
        self,
        url: str,
        mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute Gobuster directory/DNS/vhost scan."""
        return self._post(
            "api/tools/gobuster",
            {
                "url": url,
                "mode": mode,
                "wordlist": wordlist,
                "additional_args": additional_args,
                "use_recovery": True,
            },
        )

    def nuclei_scan(
        self,
        target: str,
        severity: str = "",
        tags: str = "",
        template: str = "",
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute Nuclei vulnerability scan."""
        return self._post(
            "api/tools/nuclei",
            {
                "target": target,
                "severity": severity,
                "tags": tags,
                "template": template,
                "additional_args": additional_args,
                "use_recovery": True,
            },
        )

    def sqlmap_scan(
        self,
        url: str,
        data: str = "",
        cookie: str = "",
        level: int = 1,
        risk: int = 1,
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute SQLMap SQL injection scan."""
        return self._post(
            "api/tools/sqlmap",
            {
                "url": url,
                "data": data,
                "cookie": cookie,
                "level": level,
                "risk": risk,
                "additional_args": additional_args,
            },
        )

    def ffuf_scan(
        self,
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        method: str = "GET",
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute FFUF fuzzing scan."""
        return self._post(
            "api/tools/ffuf",
            {
                "url": url,
                "wordlist": wordlist,
                "method": method,
                "additional_args": additional_args,
            },
        )

    # ==========================================================================
    # Subdomain Enumeration Tools
    # ==========================================================================

    def amass_enum(
        self,
        domain: str,
        passive: bool = True,
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute Amass subdomain enumeration."""
        return self._post(
            "api/tools/amass",
            {
                "domain": domain,
                "passive": passive,
                "additional_args": additional_args,
            },
        )

    def subfinder_scan(
        self,
        domain: str,
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute Subfinder subdomain discovery."""
        return self._post(
            "api/tools/subfinder",
            {
                "domain": domain,
                "additional_args": additional_args,
            },
        )

    # ==========================================================================
    # Web Application Security Tools
    # ==========================================================================

    def nikto_scan(
        self,
        target: str,
        port: int = 80,
        ssl: bool = False,
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute Nikto web server scan."""
        return self._post(
            "api/tools/nikto",
            {
                "target": target,
                "port": port,
                "ssl": ssl,
                "additional_args": additional_args,
            },
        )

    def wpscan_scan(
        self,
        url: str,
        enumerate: str = "vp,vt,u",
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute WPScan WordPress vulnerability scan."""
        return self._post(
            "api/tools/wpscan",
            {
                "url": url,
                "enumerate": enumerate,
                "additional_args": additional_args,
            },
        )

    # ==========================================================================
    # Password Attacks
    # ==========================================================================

    def hydra_attack(
        self,
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password_file: str = "/usr/share/wordlists/rockyou.txt",
        additional_args: str = "",
    ) -> dict[str, Any]:
        """Execute Hydra password brute-force attack."""
        return self._post(
            "api/tools/hydra",
            {
                "target": target,
                "service": service,
                "username": username,
                "username_file": username_file,
                "password_file": password_file,
                "additional_args": additional_args,
            },
        )

    # ==========================================================================
    # Generic Tool Execution
    # ==========================================================================

    def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute any HexStrike tool by name."""
        return self._post(
            f"api/tools/{tool_name}",
            arguments,
        )

    def execute_command(
        self,
        command: str,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """Execute a raw command through HexStrike."""
        return self._post(
            "api/command",
            {
                "command": command,
                "use_cache": use_cache,
            },
        )

    # ==========================================================================
    # Intelligence & Analysis
    # ==========================================================================

    def analyze_target(
        self,
        target: str,
        analysis_type: str = "comprehensive",
    ) -> dict[str, Any]:
        """Analyze a target using HexStrike's AI intelligence."""
        return self._post(
            "api/intelligence/analyze-target",
            {
                "target": target,
                "analysis_type": analysis_type,
            },
        )

    def list_tools(self) -> dict[str, Any]:
        """List all available HexStrike tools."""
        return self._get("api/tools")

    def get_status(self) -> dict[str, Any]:
        """Get HexStrike server status."""
        return self._get("health")


def get_hexstrike_client() -> HexStrikeClient:
    """Get the singleton HexStrike client instance."""
    return HexStrikeClient.get_instance()
