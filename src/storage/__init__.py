"""Storage backend interfaces and implementations for MCP OAuth Gateway."""

from .base import BaseStorage, UnifiedStorage
from .manager import StorageManager
from .memory import MemoryStorage

# Re-export for backward compatibility
ClientStorage = UnifiedStorage
SessionStorage = UnifiedStorage
TokenStorage = UnifiedStorage

__all__ = [
    "BaseStorage",
    "UnifiedStorage",
    "ClientStorage",
    "SessionStorage",
    "TokenStorage",
    "StorageManager",
    "MemoryStorage",
]
