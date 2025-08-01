"""Offline OSV client for local database scanning."""

import json
import gzip
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator
from dataclasses import dataclass
import asyncio
from concurrent.futures import ThreadPoolExecutor
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ..utils.performance import PerformanceMonitor, benchmark
from ..utils.logging import get_logger
from ..core.matcher import Vulnerability


@dataclass
class OSVDatabaseConfig:
    """Configuration for OSV database."""
    
    database_path: Path
    cache_enabled: bool = True
    max_workers: int = 4
    chunk_size: int = 1000
    
    def __post_init__(self) -> None:
        """Validate configuration."""
        if not self.database_path.exists():
            raise ValueError(f"Database path does not exist: {self.database_path}")


class OSVOfflineClient:
    """Offline client for scanning local OSV database."""
    
    def __init__(self, config: OSVDatabaseConfig) -> None:
        """Initialize the offline OSV client.
        
        Args:
            config: Database configuration
        """
        self.config = config
        self.logger = get_logger("OSVOfflineClient")
        self.performance_monitor = PerformanceMonitor()
        self._cache: Dict[str, List[Vulnerability]] = {}
        self._package_index: Dict[str, List[Vulnerability]] = {}
        self._index_built = False
    
    @benchmark
    def load_vulnerabilities(self, show_progress: bool = True) -> List[Vulnerability]:
        """Load all vulnerabilities from the local database.
        
        Args:
            show_progress: Show progress bar
            
        Returns:
            List of all vulnerabilities
        """
        with self.performance_monitor.measure("load_vulnerabilities"):
            vulnerabilities = []
            
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    transient=True
                ) as progress:
                    task = progress.add_task("Loading vulnerabilities...", total=None)
                    
                    for vuln in self._load_vulnerabilities_generator():
                        vulnerabilities.append(vuln)
                        progress.update(task, advance=1)
            else:
                vulnerabilities = list(self._load_vulnerabilities_generator())
            
            self.logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from database")
            return vulnerabilities
    
    def _load_vulnerabilities_generator(self) -> Iterator[Vulnerability]:
        """Generator for loading vulnerabilities from database files.
        
        Yields:
            Vulnerability objects
        """
        # Look for vulnerability files in the database
        vuln_files = list(self.config.database_path.rglob("*.json"))
        
        for vuln_file in vuln_files:
            try:
                with open(vuln_file, 'r', encoding='utf-8') as f:
                    vuln_data = json.load(f)
                
                vulnerability = self._parse_vulnerability(vuln_data)
                if vulnerability:
                    yield vulnerability
                else:
                    # Log the structure of failed vulnerabilities to understand the issue
                    self.logger.debug(f"Failed to parse vulnerability from {vuln_file}")
                    self.logger.debug(f"Vulnerability data keys: {list(vuln_data.keys())}")
                    if "affected" in vuln_data:
                        affected = vuln_data["affected"]
                        self.logger.debug(f"Affected type: {type(affected)}, value: {affected}")
                    
            except (json.JSONDecodeError, IOError) as e:
                self.logger.warning(f"Failed to parse {vuln_file}: {e}")
                continue
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse vulnerability data from JSON.
        
        Args:
            vuln_data: Raw vulnerability data
            
        Returns:
            Parsed Vulnerability object or None
        """
        try:
            # Handle different possible structures for affected packages
            affected_packages = vuln_data.get("affected", [])
            if isinstance(affected_packages, list):
                # This is the correct format
                pass
            elif isinstance(affected_packages, dict):
                # Convert dict to list
                affected_packages = [affected_packages]
            else:
                # Default to empty list
                affected_packages = []
            
            return Vulnerability(
                id=vuln_data.get("id", ""),
                summary=vuln_data.get("summary", ""),
                details=vuln_data.get("details", ""),
                severity=vuln_data.get("severity", "UNKNOWN"),
                affected_packages=affected_packages,
                references=vuln_data.get("references", []),
                published_date=vuln_data.get("published"),
                modified_date=vuln_data.get("modified"),
                withdrawn_date=vuln_data.get("withdrawn")
            )
        except ValueError as e:
            self.logger.warning(f"Failed to parse vulnerability {vuln_data.get('id', 'unknown')}: {e}")
            return None
    
    @benchmark
    def build_package_index(self, vulnerabilities: List[Vulnerability]) -> None:
        """Build an index of vulnerabilities by package name.
        
        Args:
            vulnerabilities: List of vulnerabilities to index
        """
        with self.performance_monitor.measure("build_package_index"):
            self._package_index.clear()
            
            for vuln in vulnerabilities:
                for affected in vuln.affected_packages:
                    package_name = affected.get("package", {}).get("name", "").lower()
                    if package_name:
                        if package_name not in self._package_index:
                            self._package_index[package_name] = []
                        self._package_index[package_name].append(vuln)
            
            self._index_built = True
            self.logger.info(f"Built index for {len(self._package_index)} packages")
    
    def find_vulnerabilities_for_package(
        self,
        package_name: str,
        ecosystem: Optional[str] = None
    ) -> List[Vulnerability]:
        """Find vulnerabilities for a specific package.
        
        Args:
            package_name: Name of the package
            ecosystem: Optional ecosystem filter
            
        Returns:
            List of vulnerabilities for the package
        """
        if not self._index_built:
            self.logger.warning("Package index not built. Call build_package_index() first.")
            return []
        
        package_name_lower = package_name.lower()
        vulnerabilities = self._package_index.get(package_name_lower, [])
        
        if ecosystem:
            # Filter by ecosystem
            filtered_vulns = []
            for vuln in vulnerabilities:
                for affected in vuln.affected_packages:
                    affected_ecosystem = affected.get("package", {}).get("ecosystem", "").lower()
                    if affected_ecosystem == ecosystem.lower():
                        filtered_vulns.append(vuln)
                        break
            return filtered_vulns
        
        return vulnerabilities
    
    def search_vulnerabilities(
        self,
        query: str,
        ecosystem: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Vulnerability]:
        """Search vulnerabilities by text query.
        
        Args:
            query: Search query
            ecosystem: Optional ecosystem filter
            limit: Maximum number of results
            
        Returns:
            List of matching vulnerabilities
        """
        results = []
        query_lower = query.lower()
        
        # Search in package names
        for package_name, vulns in self._package_index.items():
            if query_lower in package_name:
                for vuln in vulns:
                    if ecosystem:
                        # Check if vulnerability affects the specified ecosystem
                        for affected in vuln.affected_packages:
                            affected_ecosystem = affected.get("package", {}).get("ecosystem", "").lower()
                            if affected_ecosystem == ecosystem.lower():
                                results.append(vuln)
                                break
                    else:
                        results.append(vuln)
        
        # Remove duplicates
        seen_ids = set()
        unique_results = []
        for vuln in results:
            if vuln.id not in seen_ids:
                seen_ids.add(vuln.id)
                unique_results.append(vuln)
        
        if limit:
            unique_results = unique_results[:limit]
        
        return unique_results
    
    async def scan_dependencies_async(
        self,
        dependencies: List[Dict[str, str]],
        show_progress: bool = True
    ) -> List[Vulnerability]:
        """Scan dependencies for vulnerabilities asynchronously.
        
        Args:
            dependencies: List of dependency dictionaries
            show_progress: Show progress bar
            
        Returns:
            List of found vulnerabilities
        """
        if not self._index_built:
            self.logger.warning("Package index not built. Call build_package_index() first.")
            return []
        
        vulnerabilities = []
        
        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                transient=True
            ) as progress:
                task = progress.add_task("Scanning dependencies...", total=len(dependencies))
                
                for dep in dependencies:
                    package_name = dep["name"]
                    ecosystem = dep.get("ecosystem")
                    
                    dep_vulns = self.find_vulnerabilities_for_package(package_name, ecosystem)
                    vulnerabilities.extend(dep_vulns)
                    
                    progress.update(task, advance=1)
        else:
            for dep in dependencies:
                package_name = dep["name"]
                ecosystem = dep.get("ecosystem")
                
                dep_vulns = self.find_vulnerabilities_for_package(package_name, ecosystem)
                vulnerabilities.extend(dep_vulns)
        
        # Remove duplicates
        seen_ids = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            if vuln.id not in seen_ids:
                seen_ids.add(vuln.id)
                unique_vulns.append(vuln)
        
        self.logger.info(f"Found {len(unique_vulns)} unique vulnerabilities")
        return unique_vulns
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics.
        
        Returns:
            Dictionary with database statistics
        """
        if not self._index_built:
            return {"error": "Package index not built"}
        
        total_packages = len(self._package_index)
        total_vulnerabilities = sum(len(vulns) for vulns in self._package_index.values())
        
        # Count unique vulnerabilities
        unique_vuln_ids = set()
        for vulns in self._package_index.values():
            for vuln in vulns:
                unique_vuln_ids.add(vuln.id)
        
        return {
            "total_packages": total_packages,
            "total_vulnerabilities": total_vulnerabilities,
            "unique_vulnerabilities": len(unique_vuln_ids),
            "average_vulnerabilities_per_package": total_vulnerabilities / total_packages if total_packages > 0 else 0
        }
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary.
        
        Returns:
            Performance summary dictionary
        """
        return self.performance_monitor.get_summary()
    
    def print_performance_summary(self) -> None:
        """Print performance summary to console."""
        self.performance_monitor.print_summary()
    
    def clear_cache(self) -> None:
        """Clear internal caches."""
        self._cache.clear()
        self._package_index.clear()
        self._index_built = False 