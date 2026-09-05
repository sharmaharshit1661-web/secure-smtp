"""
Centralized Configuration & Settings Module (Compatibility Re-export).

Re-exports Settings and get_settings from the primary secure_smtp.config module.
"""

from secure_smtp.config import Settings, get_settings

__all__ = ["Settings", "get_settings"]
