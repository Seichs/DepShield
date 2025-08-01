"""Python dependency file parsers."""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from .base import BaseParser, Dependency, ParsedDependencies


class PythonRequirementsParser(BaseParser):
    """Parser for Python requirements.txt files."""
    
    def __init__(self) -> None:
        """Initialize the requirements parser."""
        super().__init__()
        self.ecosystem = "python"
        self.parser_type = "requirements"
        self.supported_extensions = [".txt"]
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is a requirements file
        """
        filename = file_path.name.lower()
        return filename.startswith("requirements") and filename.endswith(".txt")
    
    def parse(self, file_path: Path) -> ParsedDependencies:
        """Parse a requirements.txt file.
        
        Args:
            file_path: Path to the requirements file
            
        Returns:
            Parsed dependencies
        """
        self.validate_file(file_path)
        
        result = ParsedDependencies(
            source_file=file_path,
            ecosystem=self.ecosystem,
            parser_type=self.parser_type
        )
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Parse dependency line
                dependency = self._parse_requirement_line(line, line_num)
                if dependency:
                    result.add_dependency(dependency)
        
        return result
    
    def _parse_requirement_line(self, line: str, line_num: int) -> Optional[Dependency]:
        """Parse a single requirement line.
        
        Args:
            line: Requirement line to parse
            line_num: Line number for error reporting
            
        Returns:
            Parsed dependency or None if invalid
        """
        # Remove comments
        line = re.sub(r'#.*$', '', line).strip()
        if not line:
            return None
        
        # Handle editable installs
        if line.startswith('-e ') or line.startswith('--editable '):
            return self._parse_editable_requirement(line, line_num)
        
        # Handle direct URLs
        if line.startswith(('http://', 'https://', 'git+', 'svn+', 'hg+')):
            return self._parse_url_requirement(line, line_num)
        
        # Handle standard requirements
        return self._parse_standard_requirement(line, line_num)
    
    def _parse_standard_requirement(self, line: str, line_num: int) -> Optional[Dependency]:
        """Parse a standard requirement line.
        
        Args:
            line: Requirement line
            line_num: Line number
            
        Returns:
            Parsed dependency
        """
        # Pattern: package[extras]>=version
        pattern = r'^([a-zA-Z0-9._-]+)(?:\[([^\]]+)\])?([<>=!~]+.*)?$'
        match = re.match(pattern, line)
        
        if not match:
            return None
        
        name = match.group(1)
        extras = match.group(2)
        version_spec = match.group(3)
        
        # Normalize name
        name = self._normalize_package_name(name)
        
        # Extract version from specifier
        version = None
        if version_spec:
            version = self._parse_version_specifier(version_spec)
        
        return Dependency(
            name=name,
            version=version,
            version_specifier=version_spec,
            ecosystem=self.ecosystem,
            source_file=Path("requirements.txt"),  # Will be set by caller
            line_number=line_num,
            metadata={"extras": extras} if extras else {}
        )
    
    def _parse_editable_requirement(self, line: str, line_num: int) -> Optional[Dependency]:
        """Parse an editable requirement line.
        
        Args:
            line: Editable requirement line
            line_num: Line number
            
        Returns:
            Parsed dependency
        """
        # Pattern: -e git+https://github.com/user/repo.git#egg=package
        # or: -e ./local/path#egg=package
        
        # Extract package name from egg fragment
        egg_match = re.search(r'#egg=([a-zA-Z0-9._-]+)', line)
        if egg_match:
            name = self._normalize_package_name(egg_match.group(1))
        else:
            # Try to extract from URL or path
            parts = line.split()
            if len(parts) >= 2:
                path = parts[1]
                name = Path(path).name
                name = self._normalize_package_name(name)
            else:
                return None
        
        return Dependency(
            name=name,
            version=None,
            version_specifier=None,
            ecosystem=self.ecosystem,
            source_file=Path("requirements.txt"),
            line_number=line_num,
            metadata={"editable": True, "source": line}
        )
    
    def _parse_url_requirement(self, line: str, line_num: int) -> Optional[Dependency]:
        """Parse a URL requirement line.
        
        Args:
            line: URL requirement line
            line_num: Line number
            
        Returns:
            Parsed dependency
        """
        # Extract package name from egg fragment or URL
        egg_match = re.search(r'#egg=([a-zA-Z0-9._-]+)', line)
        if egg_match:
            name = self._normalize_package_name(egg_match.group(1))
        else:
            # Try to extract from URL path
            url_match = re.search(r'/([^/]+?)(?:\.git)?$', line)
            if url_match:
                name = self._normalize_package_name(url_match.group(1))
            else:
                return None
        
        return Dependency(
            name=name,
            version=None,
            version_specifier=None,
            ecosystem=self.ecosystem,
            source_file=Path("requirements.txt"),
            line_number=line_num,
            metadata={"source": line, "url": True}
        )


class PythonPyProjectParser(BaseParser):
    """Parser for Python pyproject.toml files."""
    
    def __init__(self) -> None:
        """Initialize the pyproject parser."""
        super().__init__()
        self.ecosystem = "python"
        self.parser_type = "pyproject"
        self.supported_extensions = [".toml"]
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is a pyproject.toml file
        """
        return file_path.name == "pyproject.toml"
    
    def parse(self, file_path: Path) -> ParsedDependencies:
        """Parse a pyproject.toml file.
        
        Args:
            file_path: Path to the pyproject.toml file
            
        Returns:
            Parsed dependencies
        """
        self.validate_file(file_path)
        
        result = ParsedDependencies(
            source_file=file_path,
            ecosystem=self.ecosystem,
            parser_type=self.parser_type
        )
        
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        
        with open(file_path, 'rb') as f:
            data = tomllib.load(f)
        
        # Extract dependencies from various sections
        dependencies = self._extract_dependencies(data)
        
        for dep_data in dependencies:
            dependency = self._create_dependency(dep_data)
            if dependency:
                result.add_dependency(dependency)
        
        return result
    
    def _extract_dependencies(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract dependencies from pyproject.toml data.
        
        Args:
            data: Parsed TOML data
            
        Returns:
            List of dependency data dictionaries
        """
        dependencies = []
        
        # Check project.dependencies
        if "project" in data and "dependencies" in data["project"]:
            for dep in data["project"]["dependencies"]:
                dependencies.append(self._parse_dependency_string(dep))
        
        # Check project.optional-dependencies
        if "project" in data and "optional-dependencies" in data["project"]:
            for group_name, group_deps in data["project"]["optional-dependencies"].items():
                for dep in group_deps:
                    dep_data = self._parse_dependency_string(dep)
                    dep_data["group"] = group_name
                    dependencies.append(dep_data)
        
        # Check tool.poetry.dependencies
        if "tool" in data and "poetry" in data["tool"] and "dependencies" in data["tool"]["poetry"]:
            for name, spec in data["tool"]["poetry"]["dependencies"].items():
                if isinstance(spec, str):
                    dep_data = self._parse_dependency_string(f"{name}{spec}")
                else:
                    dep_data = {"name": name, "version": str(spec.get("version", ""))}
                dependencies.append(dep_data)
        
        return dependencies
    
    def _parse_dependency_string(self, dep_string: str) -> Dict[str, Any]:
        """Parse a dependency string from pyproject.toml.
        
        Args:
            dep_string: Dependency string (e.g., "requests>=2.25.0")
            
        Returns:
            Dictionary with parsed dependency data
        """
        # Pattern: package[extras]>=version
        pattern = r'^([a-zA-Z0-9._-]+)(?:\[([^\]]+)\])?([<>=!~]+.*)?$'
        match = re.match(pattern, dep_string)
        
        if not match:
            return {"name": dep_string, "version": None}
        
        name = match.group(1)
        extras = match.group(2)
        version_spec = match.group(3)
        
        return {
            "name": name,
            "version": self._parse_version_specifier(version_spec) if version_spec else None,
            "version_specifier": version_spec,
            "extras": extras
        }
    
    def _create_dependency(self, dep_data: Dict[str, Any]) -> Optional[Dependency]:
        """Create a Dependency object from parsed data.
        
        Args:
            dep_data: Parsed dependency data
            
        Returns:
            Dependency object or None if invalid
        """
        name = dep_data.get("name")
        if not name:
            return None
        
        name = self._normalize_package_name(name)
        
        return Dependency(
            name=name,
            version=dep_data.get("version"),
            version_specifier=dep_data.get("version_specifier"),
            ecosystem=self.ecosystem,
            source_file=Path("pyproject.toml"),
            metadata={
                "extras": dep_data.get("extras"),
                "group": dep_data.get("group")
            }
        ) 