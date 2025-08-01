"""Path utilities for finding dependency files and filtering paths."""

import os
import fnmatch
from pathlib import Path
from typing import List, Set, Iterator, Optional
from dataclasses import dataclass


@dataclass
class DependencyFile:
    """Represents a dependency file with metadata."""
    
    path: Path
    ecosystem: str
    parser_type: str
    
    def __post_init__(self) -> None:
        """Validate the dependency file."""
        if not self.path.exists():
            raise ValueError(f"Dependency file does not exist: {self.path}")


class PathFilter:
    """Filters paths based on patterns and rules."""
    
    def __init__(self, ignore_patterns: Optional[List[str]] = None) -> None:
        """Initialize path filter.
        
        Args:
            ignore_patterns: List of glob patterns to ignore
        """
        self.ignore_patterns = ignore_patterns or [
            "**/node_modules/**",
            "**/.git/**",
            "**/__pycache__/**",
            "**/.venv/**",
            "**/venv/**",
            "**/env/**",
            "**/.env/**",
            "**/dist/**",
            "**/build/**",
            "**/.pytest_cache/**",
            "**/.coverage",
            "**/*.pyc",
            "**/*.pyo",
            "**/*.pyd",
            "**/.DS_Store",
            "**/Thumbs.db",
        ]
    
    def is_ignored(self, path: Path) -> bool:
        """Check if a path should be ignored.
        
        Args:
            path: Path to check
            
        Returns:
            True if path should be ignored
        """
        path_str = str(path)
        
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path_str, pattern):
                return True
        
        return False
    
    def filter_paths(self, paths: Iterator[Path]) -> Iterator[Path]:
        """Filter paths based on ignore patterns.
        
        Args:
            paths: Iterator of paths to filter
            
        Yields:
            Paths that should not be ignored
        """
        for path in paths:
            if not self.is_ignored(path):
                yield path


class DependencyFileFinder:
    """Finds dependency files in a project directory."""
    
    # Supported dependency file patterns
    DEPENDENCY_PATTERNS = {
        # Python
        "requirements.txt": ("python", "requirements"),
        "requirements-dev.txt": ("python", "requirements"),
        "requirements-test.txt": ("python", "requirements"),
        "pyproject.toml": ("python", "pyproject"),
        "setup.py": ("python", "setup"),
        "Pipfile": ("python", "pipfile"),
        "Pipfile.lock": ("python", "pipfile"),
        "poetry.lock": ("python", "poetry"),
        
        # Node.js
        "package.json": ("nodejs", "package"),
        "package-lock.json": ("nodejs", "package"),
        "yarn.lock": ("nodejs", "yarn"),
        "pnpm-lock.yaml": ("nodejs", "pnpm"),
        
        # Ruby
        "Gemfile": ("ruby", "gemfile"),
        "Gemfile.lock": ("ruby", "gemfile"),
        
        # Java
        "pom.xml": ("java", "maven"),
        "build.gradle": ("java", "gradle"),
        "build.gradle.kts": ("java", "gradle"),
        
        # Go
        "go.mod": ("go", "gomod"),
        "go.sum": ("go", "gosum"),
        
        # Rust
        "Cargo.toml": ("rust", "cargo"),
        "Cargo.lock": ("rust", "cargo"),
        
        # PHP
        "composer.json": ("php", "composer"),
        "composer.lock": ("php", "composer"),
        
        # .NET
        "*.csproj": ("dotnet", "csproj"),
        "*.vbproj": ("dotnet", "vbproj"),
        "packages.config": ("dotnet", "packages"),
        
        # Docker
        "Dockerfile": ("docker", "dockerfile"),
        "docker-compose.yml": ("docker", "docker-compose"),
        "docker-compose.yaml": ("docker", "docker-compose"),
    }
    
    def __init__(self, ignore_patterns: Optional[List[str]] = None) -> None:
        """Initialize dependency file finder.
        
        Args:
            ignore_patterns: Additional ignore patterns
        """
        self.path_filter = PathFilter(ignore_patterns)
    
    def find_dependency_files(self, root_path: Path) -> List[DependencyFile]:
        """Find all dependency files in a directory tree.
        
        Args:
            root_path: Root directory to search
            
        Returns:
            List of found dependency files
        """
        if not root_path.exists():
            raise ValueError(f"Root path does not exist: {root_path}")
        
        dependency_files = []
        
        for file_path in self._walk_files(root_path):
            ecosystem, parser_type = self._get_file_type(file_path)
            if ecosystem and parser_type:
                try:
                    dep_file = DependencyFile(
                        path=file_path,
                        ecosystem=ecosystem,
                        parser_type=parser_type
                    )
                    dependency_files.append(dep_file)
                except ValueError:
                    # Skip invalid files
                    continue
        
        return dependency_files
    
    def _walk_files(self, root_path: Path) -> Iterator[Path]:
        """Walk through files in directory tree.
        
        Args:
            root_path: Root directory to walk
            
        Yields:
            File paths that are not ignored
        """
        for file_path in root_path.rglob("*"):
            if file_path.is_file() and not self.path_filter.is_ignored(file_path):
                yield file_path
    
    def _get_file_type(self, file_path: Path) -> tuple[Optional[str], Optional[str]]:
        """Get ecosystem and parser type for a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (ecosystem, parser_type) or (None, None) if not supported
        """
        filename = file_path.name
        
        # Check exact matches first
        if filename in self.DEPENDENCY_PATTERNS:
            return self.DEPENDENCY_PATTERNS[filename]
        
        # Check pattern matches
        for pattern, (ecosystem, parser_type) in self.DEPENDENCY_PATTERNS.items():
            if fnmatch.fnmatch(filename, pattern):
                return ecosystem, parser_type
        
        return None, None
    
    def get_supported_ecosystems(self) -> Set[str]:
        """Get list of supported ecosystems.
        
        Returns:
            Set of supported ecosystem names
        """
        return {ecosystem for ecosystem, _ in self.DEPENDENCY_PATTERNS.values()}
    
    def get_supported_parsers(self) -> Set[str]:
        """Get list of supported parser types.
        
        Returns:
            Set of supported parser types
        """
        return {parser_type for _, parser_type in self.DEPENDENCY_PATTERNS.values()}


def find_dependency_files(
    root_path: Path,
    ignore_patterns: Optional[List[str]] = None
) -> List[DependencyFile]:
    """Convenience function to find dependency files.
    
    Args:
        root_path: Root directory to search
        ignore_patterns: Additional ignore patterns
        
    Returns:
        List of found dependency files
    """
    finder = DependencyFileFinder(ignore_patterns)
    return finder.find_dependency_files(root_path)


def is_ignored_path(path: Path, ignore_patterns: Optional[List[str]] = None) -> bool:
    """Check if a path should be ignored.
    
    Args:
        path: Path to check
        ignore_patterns: Additional ignore patterns
        
    Returns:
        True if path should be ignored
    """
    filter_obj = PathFilter(ignore_patterns)
    return filter_obj.is_ignored(path) 