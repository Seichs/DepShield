"""Core vulnerability matching logic for DepShield."""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, AsyncGenerator
from pathlib import Path
from packaging import version as packaging_version
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from ..utils.performance import PerformanceMonitor, benchmark
from ..utils.logging import get_logger
from .parsers import Dependency, ParsedDependencies


@dataclass
class Vulnerability:
    """Represents a vulnerability with metadata."""
    
    id: str
    summary: str
    details: str
    severity: str
    affected_packages: List[Dict[str, Any]]
    references: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    withdrawn_date: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Validate vulnerability data."""
        if not self.id:
            raise ValueError("Vulnerability ID cannot be empty")
        # Use a default summary if none provided
        if not self.summary:
            self.summary = "No summary available"


@dataclass
class VulnerabilityMatch:
    """Represents a match between a dependency and a vulnerability."""
    
    dependency: Dependency
    vulnerability: Vulnerability
    confidence: float
    match_reason: str
    affected_versions: List[str] = field(default_factory=list)
    
    def __post_init__(self) -> None:
        """Validate match data."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")


class VulnerabilityMatcher:
    """High-performance vulnerability matcher with async support."""
    
    def __init__(self, enable_performance_monitoring: bool = True) -> None:
        """Initialize the vulnerability matcher.
        
        Args:
            enable_performance_monitoring: Enable performance tracking
        """
        self.logger = get_logger("VulnerabilityMatcher")
        self.performance_monitor = PerformanceMonitor(enable_performance_monitoring)
        self._cache: Dict[str, List[Vulnerability]] = {}
        self._package_index: Dict[str, List[Vulnerability]] = {}
    
    @benchmark
    def match_dependencies(
        self,
        dependencies: List[Dependency],
        vulnerabilities: List[Vulnerability]
    ) -> List[VulnerabilityMatch]:
        """Match dependencies against vulnerabilities.
        
        Args:
            dependencies: List of dependencies to check
            vulnerabilities: List of vulnerabilities to match against
            
        Returns:
            List of vulnerability matches
        """
        with self.performance_monitor.measure("match_dependencies"):
            matches = []
            
            # Build package index for faster lookup
            self._build_package_index(vulnerabilities)
            
            for dependency in dependencies:
                dependency_matches = self._match_dependency(dependency)
                matches.extend(dependency_matches)
            
            return matches
    
    async def match_dependencies_async(
        self,
        dependencies: List[Dependency],
        vulnerabilities: List[Vulnerability]
    ) -> List[VulnerabilityMatch]:
        """Async version of match_dependencies for I/O bound operations.
        
        Args:
            dependencies: List of dependencies to check
            vulnerabilities: List of vulnerabilities to match against
            
        Returns:
            List of vulnerability matches
        """
        with self.performance_monitor.measure("match_dependencies_async"):
            # Build package index
            self._build_package_index(vulnerabilities)
            
            # Process dependencies concurrently
            tasks = [
                self._match_dependency_async(dependency)
                for dependency in dependencies
            ]
            
            results = await asyncio.gather(*tasks)
            
            # Flatten results
            matches = []
            for dependency_matches in results:
                matches.extend(dependency_matches)
            
            return matches
    
    def _build_package_index(self, vulnerabilities: List[Vulnerability]) -> None:
        """Build an index of vulnerabilities by package name for faster lookup.
        
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
    
    def _match_dependency(self, dependency: Dependency) -> List[VulnerabilityMatch]:
        """Match a single dependency against vulnerabilities.
        
        Args:
            dependency: Dependency to match
            
        Returns:
            List of vulnerability matches for this dependency
        """
        matches = []
        
        # Get vulnerabilities for this package
        package_vulns = self._package_index.get(dependency.name.lower(), [])
        
        if package_vulns:
            self.logger.debug(f"Found {len(package_vulns)} vulnerabilities for {dependency.name} (version: {dependency.version})")
        
        for vuln in package_vulns:
            match = self._check_vulnerability_match(dependency, vuln)
            if match:
                self.logger.debug(f"MATCH: {dependency.name} {dependency.version} matches {vuln.id}")
                matches.append(match)
            else:
                self.logger.debug(f"NO MATCH: {dependency.name} {dependency.version} does not match {vuln.id}")
        
        return matches
    
    async def _match_dependency_async(self, dependency: Dependency) -> List[VulnerabilityMatch]:
        """Async version of _match_dependency.
        
        Args:
            dependency: Dependency to match
            
        Returns:
            List of vulnerability matches for this dependency
        """
        # Simulate async processing (in real implementation, this might involve
        # async database queries or API calls)
        await asyncio.sleep(0)  # Yield control
        return self._match_dependency(dependency)
    
    def _check_vulnerability_match(
        self,
        dependency: Dependency,
        vulnerability: Vulnerability
    ) -> Optional[VulnerabilityMatch]:
        """Check if a dependency matches a specific vulnerability.
        
        Args:
            dependency: Dependency to check
            vulnerability: Vulnerability to match against
            
        Returns:
            VulnerabilityMatch if matched, None otherwise
        """
        for affected in vulnerability.affected_packages:
            self.logger.debug(f"Checking affected package: {type(affected)} - {affected}")
            match = self._check_affected_package(dependency, vulnerability, affected)
            if match:
                return match
        
        return None
    
    def _check_affected_package(
        self,
        dependency: Dependency,
        vulnerability: Vulnerability,
        affected: Dict[str, Any]
    ) -> Optional[VulnerabilityMatch]:
        """Check if dependency matches an affected package specification.
        
        Args:
            dependency: Dependency to check
            vulnerability: Vulnerability being checked
            affected: Affected package specification
            
        Returns:
            VulnerabilityMatch if matched, None otherwise
        """
        # Ensure affected is a dictionary
        if not isinstance(affected, dict):
            self.logger.debug(f"Skipping non-dict affected package: {type(affected)}")
            return None
        
        # Check package name
        affected_package = affected.get("package", {})
        affected_name = affected_package.get("name", "").lower()
        
        if dependency.name.lower() != affected_name:
            return None
        
        # Check ecosystem
        affected_ecosystem = affected_package.get("ecosystem", "").lower()
        
        # Map our ecosystem names to OSV ecosystem names for comparison
        ecosystem_mapping = {
            "python": "pypi",
            "nodejs": "npm", 
            "ruby": "rubygems",
            "java": "maven",
            "go": "go",
            "rust": "crates.io",
            "php": "packagist",
            "dotnet": "nuget"
        }
        
        dependency_ecosystem = dependency.ecosystem.lower()
        mapped_ecosystem = ecosystem_mapping.get(dependency_ecosystem, dependency_ecosystem)
        
        if affected_ecosystem and mapped_ecosystem != affected_ecosystem:
            return None
        
        # Check version ranges
        affected_ranges = affected.get("ranges", [])
        if not affected_ranges:
            # No version constraints, consider it a match
            return VulnerabilityMatch(
                dependency=dependency,
                vulnerability=vulnerability,
                confidence=0.8,
                match_reason="No version constraints specified"
            )
        
        # Check each version range
        for version_range in affected_ranges:
            match = self._check_version_range(dependency, vulnerability, version_range)
            if match:
                return match
        
        return None
    
    def _check_version_range(
        self,
        dependency: Dependency,
        vulnerability: Vulnerability,
        version_range: Dict[str, Any]
    ) -> Optional[VulnerabilityMatch]:
        """Check if dependency version matches a vulnerability version range.
        
        Args:
            dependency: Dependency to check
            vulnerability: Vulnerability being checked
            version_range: Version range specification
            
        Returns:
            VulnerabilityMatch if matched, None otherwise
        """
        if not dependency.version:
            # If no version is available, we can't determine if it's vulnerable
            # This is a conservative approach - assume it might be vulnerable
            self.logger.debug(f"No version available for {dependency.name}, skipping version check")
            return None
        
        try:
            current_version = Version(dependency.version)
        except packaging_version.InvalidVersion:
            self.logger.debug(f"Invalid version format for {dependency.name}: {dependency.version}")
            return None
        
        # Handle OSV format: ranges with events
        events = version_range.get("events", [])
        if events:
            introduced = None
            fixed = None
            
            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    fixed = event["fixed"]
            
            # Check if current version is in vulnerable range
            is_vulnerable = True
            
            self.logger.debug(f"Checking {dependency.name} {current_version} against introduced={introduced}, fixed={fixed}")
            
            if introduced:
                try:
                    # Skip if introduced version looks like a Git commit hash
                    if len(introduced) == 40 and all(c in '0123456789abcdef' for c in introduced.lower()):
                        self.logger.debug(f"Skipping Git commit hash as introduced version: {introduced}")
                        return None
                    
                    introduced_version = Version(introduced)
                    if current_version < introduced_version:
                        is_vulnerable = False
                        self.logger.debug(f"Version {current_version} < {introduced_version} (introduced), not vulnerable")
                except packaging_version.InvalidVersion:
                    self.logger.debug(f"Invalid introduced version: {introduced}")
                    pass
            
            if fixed:
                try:
                    # Skip if fixed version looks like a Git commit hash
                    if len(fixed) == 40 and all(c in '0123456789abcdef' for c in fixed.lower()):
                        self.logger.debug(f"Skipping Git commit hash as fixed version: {fixed}")
                        return None
                    
                    fixed_version = Version(fixed)
                    if current_version >= fixed_version:
                        is_vulnerable = False
                        self.logger.debug(f"Version {current_version} >= {fixed_version} (fixed), not vulnerable")
                except packaging_version.InvalidVersion:
                    self.logger.debug(f"Invalid fixed version: {fixed}")
                    pass
            
            # Only return match if version is actually vulnerable
            if is_vulnerable:
                self.logger.debug(f"VULNERABLE: {dependency.name} {dependency.version} is in range ({introduced} - {fixed})")
                return VulnerabilityMatch(
                    dependency=dependency,
                    vulnerability=vulnerability,
                    confidence=0.9,
                    match_reason=f"Version {dependency.version} is in vulnerable range ({introduced} - {fixed})",
                    affected_versions=[f"{introduced or '0.0.0'} - {fixed or 'latest'}"]
                )
            else:
                self.logger.debug(f"NOT VULNERABLE: {dependency.name} {dependency.version} is not in range ({introduced} - {fixed})")
            
            return None
        
        # Handle legacy format: direct introduced/fixed
        introduced = version_range.get("introduced")
        fixed = version_range.get("fixed")
        
        is_vulnerable = True
        
        if introduced:
            try:
                # Skip if introduced version looks like a Git commit hash
                if len(introduced) == 40 and all(c in '0123456789abcdef' for c in introduced.lower()):
                    self.logger.debug(f"Skipping Git commit hash as introduced version: {introduced}")
                    return None
                
                introduced_version = Version(introduced)
                if current_version < introduced_version:
                    is_vulnerable = False
            except packaging_version.InvalidVersion:
                pass
        
        if fixed:
            try:
                # Skip if fixed version looks like a Git commit hash
                if len(fixed) == 40 and all(c in '0123456789abcdef' for c in fixed.lower()):
                    self.logger.debug(f"Skipping Git commit hash as fixed version: {fixed}")
                    return None
                
                fixed_version = Version(fixed)
                if current_version >= fixed_version:
                    is_vulnerable = False
            except packaging_version.InvalidVersion:
                pass
        
        # Check affected versions
        affected_versions = version_range.get("affected", [])
        if affected_versions:
            for affected_version in affected_versions:
                if isinstance(affected_version, str) and self._version_matches_specifier(current_version, affected_version):
                    return VulnerabilityMatch(
                        dependency=dependency,
                        vulnerability=vulnerability,
                        confidence=0.95,
                        match_reason=f"Version {dependency.version} matches affected range",
                        affected_versions=[affected_version]
                    )
        
        # Only return match if version is actually vulnerable
        if is_vulnerable:
            self.logger.debug(f"VULNERABLE (legacy): {dependency.name} {dependency.version} is in range ({introduced} - {fixed})")
            return VulnerabilityMatch(
                dependency=dependency,
                vulnerability=vulnerability,
                confidence=0.9,
                match_reason=f"Version {dependency.version} is in vulnerable range",
                affected_versions=[f"{introduced} - {fixed}"]
            )
        else:
            self.logger.debug(f"NOT VULNERABLE (legacy): {dependency.name} {dependency.version} is not in range ({introduced} - {fixed})")
        
        return None
    
    def _version_matches_specifier(self, version: Version, specifier: str) -> bool:
        """Check if version matches a specifier.
        
        Args:
            version: Version to check
            specifier: Version specifier
            
        Returns:
            True if version matches specifier
        """
        try:
            specifier_set = SpecifierSet(specifier)
            return version in specifier_set
        except ValueError:
            return False
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary from the matcher.
        
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
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get matcher statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "cache_size": len(self._cache),
            "package_index_size": len(self._package_index),
            "total_packages_indexed": sum(len(vulns) for vulns in self._package_index.values())
        } 