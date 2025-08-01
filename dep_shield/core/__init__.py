"""Core parsing and version matching logic for DepShield."""

from .matcher import VulnerabilityMatcher
from .parsers import DependencyParser, Dependency, ParsedDependencies

__all__ = [
    "VulnerabilityMatcher",
    "DependencyParser", 
    "Dependency",
    "ParsedDependencies",
] 