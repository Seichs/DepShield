"""Online OSV API client for DepShield."""

import asyncio
import json
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass
import aiohttp
from aiohttp import ClientTimeout
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..utils.performance import PerformanceMonitor, benchmark
from ..utils.logging import get_logger
from ..core.matcher import Vulnerability


@dataclass
class OSVQuery:
    """Represents an OSV API query."""
    
    package_name: str
    ecosystem: Optional[str] = None
    version: Optional[str] = None
    commit: Optional[str] = None
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    limit: int = 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert query to dictionary for API request.
        
        Returns:
            Dictionary representation of the query
        """
        query = {"package": {"name": self.package_name}}
        
        if self.ecosystem:
            query["package"]["ecosystem"] = self.ecosystem
        
        if self.version:
            query["package"]["version"] = self.version
        
        if self.commit:
            query["commit"] = self.commit
        
        if self.introduced:
            query["introduced"] = self.introduced
        
        if self.fixed:
            query["fixed"] = self.fixed
        
        return query


class OSVOnlineClient:
    """Async client for the OSV.dev API."""
    
    BASE_URL = "https://api.osv.dev"
    TIMEOUT = ClientTimeout(total=30)
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None) -> None:
        """Initialize the OSV online client.
        
        Args:
            session: Optional aiohttp session for connection reuse
        """
        self.logger = get_logger("OSVOnlineClient")
        self.performance_monitor = PerformanceMonitor()
        self._session = session
        self._rate_limit_delay = 0.1  # 100ms between requests
        
        # SSL context for macOS compatibility
        import ssl
        import certifi
        
        # Create SSL context with certifi certificates
        self._ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        # Disable SSL verification for macOS compatibility
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        
    async def __aenter__(self):
        """Async context manager entry."""
        if not self._session:
            self._session = aiohttp.ClientSession(timeout=self.TIMEOUT)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    @benchmark
    async def query_vulnerabilities(self, query: OSVQuery) -> List[Vulnerability]:
        """Query vulnerabilities from OSV API.
        
        Args:
            query: OSV query object
            
        Returns:
            List of vulnerabilities
        """
        with self.performance_monitor.measure("query_vulnerabilities"):
            url = f"{self.BASE_URL}/v1/query"
            
            async with self._get_session() as session:
                async with session.post(url, json=query.to_dict()) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        self.logger.error(f"OSV API error: {response.status} - {error_text}")
                        return []
                    
                    data = await response.json()
                    vulnerabilities = self._parse_vulnerabilities(data.get("vulns", []))
                    
                    return vulnerabilities
    
    async def query_vulnerabilities_batch(
        self,
        queries: List[OSVQuery],
        max_concurrent: int = 10
    ) -> List[Vulnerability]:
        """Query multiple vulnerabilities concurrently.
        
        Args:
            queries: List of OSV queries
            max_concurrent: Maximum concurrent requests
            
        Returns:
            List of all vulnerabilities
        """
        with self.performance_monitor.measure("query_vulnerabilities_batch"):
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def query_with_semaphore(query: OSVQuery) -> List[Vulnerability]:
                async with semaphore:
                    await asyncio.sleep(self._rate_limit_delay)  # Rate limiting
                    return await self.query_vulnerabilities(query)
            
            tasks = [query_with_semaphore(query) for query in queries]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Flatten results and handle exceptions
            all_vulnerabilities = []
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"Query failed: {result}")
                else:
                    all_vulnerabilities.extend(result)
            
            return all_vulnerabilities
    
    async def query_vulnerabilities_for_packages(
        self,
        packages: List[Dict[str, str]]
    ) -> List[Vulnerability]:
        """Query vulnerabilities for a list of packages.
        
        Args:
            packages: List of package dictionaries with 'name' and optional 'ecosystem'
            show_progress: Show progress bar
            
        Returns:
            List of vulnerabilities
        """
        queries = []
        for package in packages:
            query = OSVQuery(
                package_name=package["name"],
                ecosystem=package.get("ecosystem")
            )
            queries.append(query)
        
        vulnerabilities = await self.query_vulnerabilities_batch(queries)
        
        return vulnerabilities
    
    def _parse_vulnerabilities(self, vuln_data: List[Dict[str, Any]]) -> List[Vulnerability]:
        """Parse vulnerability data from OSV API response.
        
        Args:
            vuln_data: Raw vulnerability data from API
            
        Returns:
            List of parsed Vulnerability objects
        """
        vulnerabilities = []
        
        for vuln in vuln_data:
            try:
                vulnerability = Vulnerability(
                    id=vuln.get("id", ""),
                    summary=vuln.get("summary", "No summary available"),
                    details=vuln.get("details", ""),
                    severity=vuln.get("severity", "UNKNOWN"),
                    affected_packages=vuln.get("affected", []),
                    references=vuln.get("references", []),
                    published_date=vuln.get("published"),
                    modified_date=vuln.get("modified"),
                    withdrawn_date=vuln.get("withdrawn")
                )
                vulnerabilities.append(vulnerability)
            except ValueError as e:
                # Only log critical errors, not missing summaries
                if "ID cannot be empty" in str(e):
                    self.logger.warning(f"Failed to parse vulnerability {vuln.get('id', 'unknown')}: {e}")
                continue
        
        return vulnerabilities
    
    def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session.
        
        Returns:
            aiohttp ClientSession
        """
        if not self._session or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=self._ssl_context)
            self._session = aiohttp.ClientSession(
                timeout=self.TIMEOUT,
                connector=connector
            )
        return self._session
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary.
        
        Returns:
            Performance summary dictionary
        """
        return self.performance_monitor.get_summary()
    
    def print_performance_summary(self) -> None:
        """Print performance summary to console."""
        self.performance_monitor.print_summary()
    
    async def test_connection(self) -> bool:
        """Test connection to OSV API.
        
        Returns:
            True if connection successful
        """
        try:
            url = f"{self.BASE_URL}/v1/query"
            # Test with a known working query
            test_query = {
                "package": {
                    "name": "requests",
                    "ecosystem": "PyPI"
                }
            }
            
            async with self._get_session() as session:
                async with session.post(url, json=test_query) as response:
                    return response.status in [200, 400]  # 400 is expected for invalid query
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False 