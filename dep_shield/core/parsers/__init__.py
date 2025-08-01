"""Dependency file parsers for various ecosystems."""

from typing import Dict, Type
from .base import BaseParser, Dependency, ParsedDependencies
from .python import PythonRequirementsParser, PythonPyProjectParser
from .nodejs import NodeJSPackageParser, NodeJSYarnParser
from .registry import ParserRegistry

# Register built-in parsers
registry = ParserRegistry()

# Python parsers
registry.register("python", "requirements", PythonRequirementsParser())
registry.register("python", "pyproject", PythonPyProjectParser())

# Node.js parsers  
registry.register("nodejs", "package", NodeJSPackageParser())
registry.register("nodejs", "yarn", NodeJSYarnParser())

# Convenience exports
DependencyParser = registry
__all__ = [
    "BaseParser",
    "Dependency", 
    "ParsedDependencies",
    "DependencyParser",
    "ParserRegistry",
    "registry",
] 