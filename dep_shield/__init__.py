"""DepShield - A professional CLI tool for scanning project dependencies against known vulnerabilities."""

__version__ = "0.1.0"
__author__ = "DepShield Team"
__email__ = "team@depshield.dev"

from .core.matcher import VulnerabilityMatcher
from .core.parsers import DependencyParser
from .osv.online import OSVOnlineClient
from .osv.offline import OSVOfflineClient
from .output.formatters import ConsoleFormatter, JSONFormatter

__all__ = [
    "VulnerabilityMatcher",
    "DependencyParser", 
    "OSVOnlineClient",
    "OSVOfflineClient",
    "ConsoleFormatter",
    "JSONFormatter",
] 