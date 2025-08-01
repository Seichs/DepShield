"""Base parser class and data models for dependency parsing."""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from packaging import version as packaging_version
from packaging.specifiers import SpecifierSet
from packaging.version import Version
import os


@dataclass
class Dependency:
    """Represents a single dependency with version information."""
    
    name: str
    version: Optional[str] = None
    version_specifier: Optional[str] = None
    ecosystem: str = ""
    source_file: Optional[Path] = None
    line_number: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Validate and normalize the dependency."""
        if not self.name:
            raise ValueError("Dependency name cannot be empty")
        
        # Normalize name
        self.name = self.name.lower().strip()
        
        # Parse version specifier if provided
        if self.version_specifier and not self.version:
            self.version = self._extract_version_from_specifier(self.version_specifier)
    
    def _extract_version_from_specifier(self, specifier: str) -> Optional[str]:
        """Extract version from specifier string.
        
        Args:
            specifier: Version specifier string
            
        Returns:
            Extracted version or None
        """
        # Try to extract a specific version from specifiers like ">=1.0.0,<2.0.0"
        version_pattern = r'(\d+\.\d+\.\d+(?:[a-zA-Z0-9.-]*))'
        matches = re.findall(version_pattern, specifier)
        
        if matches:
            # Return the first version found
            return matches[0]
        
        return None
    
    def is_vulnerable(self, vulnerable_versions: List[str]) -> bool:
        """Check if this dependency is vulnerable based on version list.
        
        Args:
            vulnerable_versions: List of vulnerable version strings
            
        Returns:
            True if dependency is vulnerable
        """
        if not self.version:
            return False
        
        try:
            current_version = Version(self.version)
            
            for vuln_version in vulnerable_versions:
                try:
                    vuln_ver = Version(vuln_version)
                    if current_version == vuln_ver:
                        return True
                except packaging_version.InvalidVersion:
                    continue
                    
        except packaging_version.InvalidVersion:
            return False
        
        return False
    
    def matches_version_range(self, version_range: str) -> bool:
        """Check if dependency version matches a version range.
        
        Args:
            version_range: Version range specifier
            
        Returns:
            True if version matches range
        """
        if not self.version:
            return False
        
        try:
            specifier = SpecifierSet(version_range)
            current_version = Version(self.version)
            return current_version in specifier
        except (packaging_version.InvalidVersion, ValueError):
            return False
    
    def __hash__(self) -> int:
        """Hash based on name and ecosystem."""
        return hash((self.name, self.ecosystem))
    
    def __eq__(self, other: Any) -> bool:
        """Equality based on name and ecosystem."""
        if not isinstance(other, Dependency):
            return False
        return self.name == other.name and self.ecosystem == other.ecosystem


@dataclass
class ParsedDependencies:
    """Container for parsed dependencies from a file."""
    
    dependencies: List[Dependency] = field(default_factory=list)
    source_file: Optional[Path] = None
    ecosystem: str = ""
    parser_type: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_dependency(self, dependency: Dependency) -> None:
        """Add a dependency to the collection.
        
        Args:
            dependency: Dependency to add
        """
        self.dependencies.append(dependency)
    
    def get_dependency_names(self) -> Set[str]:
        """Get set of dependency names.
        
        Returns:
            Set of dependency names
        """
        return {dep.name for dep in self.dependencies}
    
    def find_dependency(self, name: str) -> Optional[Dependency]:
        """Find a dependency by name.
        
        Args:
            name: Dependency name to find
            
        Returns:
            Dependency if found, None otherwise
        """
        for dep in self.dependencies:
            if dep.name == name:
                return dep
        return None
    
    def filter_by_ecosystem(self, ecosystem: str) -> List[Dependency]:
        """Filter dependencies by ecosystem.
        
        Args:
            ecosystem: Ecosystem to filter by
            
        Returns:
            List of dependencies in the specified ecosystem
        """
        return [dep for dep in self.dependencies if dep.ecosystem == ecosystem]


class BaseParser(ABC):
    """Abstract base class for dependency file parsers."""
    
    def __init__(self) -> None:
        """Initialize the parser."""
        self.supported_extensions: List[str] = []
        self.ecosystem: str = ""
        self.parser_type: str = ""
    
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the given file.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if parser can handle the file
        """
        pass
    
    @abstractmethod
    def parse(self, file_path: Path) -> ParsedDependencies:
        """Parse a dependency file.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            Parsed dependencies from the file
        """
        pass
    
    def validate_file(self, file_path: Path) -> None:
        """Validate that the file exists and is readable.
        
        Args:
            file_path: Path to validate
            
        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file is not readable
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")
        
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"File is not readable: {file_path}")
    
    def _normalize_package_name(self, name: str) -> str:
        """Normalize package name for consistent comparison.
        
        Args:
            name: Package name to normalize
            
        Returns:
            Normalized package name
        """
        # Remove common prefixes/suffixes
        name = name.lower().strip()
        name = re.sub(r'^python-', '', name)
        name = re.sub(r'^node-', '', name)
        name = re.sub(r'^js-', '', name)
        
        # Replace underscores with hyphens
        name = name.replace('_', '-')
        
        return name
    
    def _parse_version_specifier(self, specifier: str) -> Optional[str]:
        """Parse version specifier to extract version.
        
        Args:
            specifier: Version specifier string
            
        Returns:
            Extracted version or None
        """
        if not specifier:
            return None
        
        # Clean up the specifier
        specifier = specifier.strip()
        
        # Common patterns for exact versions
        exact_patterns = [
            r'^([0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.-]*))$',  # Exact version
            r'^==([0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.-]*))$',  # == version
            r'^>=([0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.-]*))$',  # >= version
            r'^~([0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.-]*))$',   # ~ version
            r'^<=([0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.-]*))$',  # <= version
            r'^!=([0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.-]*))$',  # != version
        ]
        
        for pattern in exact_patterns:
            match = re.match(pattern, specifier)
            if match:
                return match.group(1)
        
        # For complex specifiers like ">=1.0.0,<2.0.0", extract the minimum version
        # This gives us a reasonable version to check against
        version_pattern = r'(\d+\.\d+\.\d+(?:[a-zA-Z0-9.-]*))'
        matches = re.findall(version_pattern, specifier)
        
        if matches:
            # For >= specifiers, use the minimum version
            if '>=' in specifier:
                return matches[0]
            # For <= specifiers, use the maximum version
            elif '<=' in specifier:
                return matches[-1]
            # For ~ specifiers, use the specified version
            elif '~' in specifier:
                return matches[0]
            # For == specifiers, use the exact version
            elif '==' in specifier:
                return matches[0]
            # For != specifiers, we can't determine a specific version
            elif '!=' in specifier:
                return None
            # Default: use the first version found
            else:
                return matches[0]
        
        return None 