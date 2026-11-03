"""AI abstraction layer for TRISHUL.

The rest of the codebase only ever talks to :class:`AIManager`, which makes
the LOCAL and PROVIDER editions interchangeable at runtime.
"""

from backend.app.ai.base import AIProvider, AIRequest, AIResponse, ProviderError
from backend.app.ai.registry import AIManager, PROVIDER_CATALOG

__all__ = [
    "AIManager",
    "AIProvider",
    "AIRequest",
    "AIResponse",
    "PROVIDER_CATALOG",
    "ProviderError",
]
