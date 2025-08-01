"""OSV (Open Source Vulnerabilities) data clients for DepShield."""

from .online import OSVOnlineClient
from .offline import OSVOfflineClient

__all__ = [
    "OSVOnlineClient",
    "OSVOfflineClient",
] 