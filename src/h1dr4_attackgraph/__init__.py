"""H1DR4 ATTACKGRAPH: durable, model-agnostic red-team context over MCP."""

from h1dr4_attackgraph.operation_red import OperationRedCampaignStore
from h1dr4_attackgraph.products import MODULE_REGISTRY, OperationRedScope, ProductSurface

__version__ = "0.1.0"

__all__ = [
    "MODULE_REGISTRY",
    "OperationRedCampaignStore",
    "OperationRedScope",
    "ProductSurface",
    "__version__",
]
