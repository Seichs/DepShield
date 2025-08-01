"""Node.js dependency file parsers."""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from .base import BaseParser, Dependency, ParsedDependencies


class NodeJSPackageParser(BaseParser):
    """Parser for Node.js package.json files."""
    
    def __init__(self) -> None:
        """Initialize the package.json parser."""
        super().__init__()
        self.ecosystem = "nodejs"
        self.parser_type = "package"
        self.supported_extensions = [".json"]
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is a package.json file
        """
        return file_path.name == "package.json"
    
    def parse(self, file_path: Path) -> ParsedDependencies:
        """Parse a package.json file.
        
        Args:
            file_path: Path to the package.json file
            
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
            data = json.load(f)
        
        # Parse dependencies
        dependencies = self._extract_dependencies(data)
        
        for dep_data in dependencies:
            dependency = self._create_dependency(dep_data)
            if dependency:
                result.add_dependency(dependency)
        
        return result
    
    def _extract_dependencies(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract dependencies from package.json data.
        
        Args:
            data: Parsed JSON data
            
        Returns:
            List of dependency data dictionaries
        """
        dependencies = []
        
        # Check various dependency sections
        dep_sections = [
            ("dependencies", "runtime"),
            ("devDependencies", "dev"),
            ("peerDependencies", "peer"),
            ("optionalDependencies", "optional"),
            ("bundledDependencies", "bundled"),
        ]
        
        for section_name, dep_type in dep_sections:
            if section_name in data and isinstance(data[section_name], dict):
                for name, version_spec in data[section_name].items():
                    dependencies.append({
                        "name": name,
                        "version": self._parse_version_specifier(version_spec),
                        "version_specifier": version_spec,
                        "type": dep_type
                    })
        
        return dependencies
    
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
            source_file=Path("package.json"),
            metadata={"type": dep_data.get("type", "runtime")}
        )


class NodeJSYarnParser(BaseParser):
    """Parser for Node.js yarn.lock files."""
    
    def __init__(self) -> None:
        """Initialize the yarn.lock parser."""
        super().__init__()
        self.ecosystem = "nodejs"
        self.parser_type = "yarn"
        self.supported_extensions = [".lock"]
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is a yarn.lock file
        """
        return file_path.name == "yarn.lock"
    
    def parse(self, file_path: Path) -> ParsedDependencies:
        """Parse a yarn.lock file.
        
        Args:
            file_path: Path to the yarn.lock file
            
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
            content = f.read()
        
        # Parse yarn.lock format
        dependencies = self._parse_yarn_lock(content)
        
        for dep_data in dependencies:
            dependency = self._create_dependency(dep_data)
            if dependency:
                result.add_dependency(dependency)
        
        return result
    
    def _parse_yarn_lock(self, content: str) -> List[Dict[str, Any]]:
        """Parse yarn.lock content.
        
        Args:
            content: Yarn lock file content
            
        Returns:
            List of dependency data dictionaries
        """
        dependencies = []
        
        # Split into blocks (each dependency is a block)
        blocks = content.split('\n\n')
        
        for block in blocks:
            block = block.strip()
            if not block:
                continue
            
            dep_data = self._parse_yarn_block(block)
            if dep_data:
                dependencies.append(dep_data)
        
        return dependencies
    
    def _parse_yarn_block(self, block: str) -> Optional[Dict[str, Any]]:
        """Parse a single yarn.lock block.
        
        Args:
            block: Yarn lock block content
            
        Returns:
            Parsed dependency data or None
        """
        lines = block.split('\n')
        if not lines:
            return None
        
        # First line contains package name and version specifier
        first_line = lines[0].strip()
        
        # Pattern: package-name@version-specifier:
        match = re.match(r'^([^@]+)@([^:]+):$', first_line)
        if not match:
            return None
        
        name = match.group(1)
        version_spec = match.group(2)
        
        # Look for resolved version
        resolved_version = None
        for line in lines[1:]:
            line = line.strip()
            if line.startswith('version '):
                resolved_version = line.split(' ', 1)[1].strip('"')
                break
        
        return {
            "name": name,
            "version": resolved_version,
            "version_specifier": version_spec,
            "resolved": resolved_version is not None
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
            source_file=Path("yarn.lock"),
            metadata={"resolved": dep_data.get("resolved", False)}
        ) 