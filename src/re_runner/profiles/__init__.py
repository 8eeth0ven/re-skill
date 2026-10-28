from pathlib import Path

from ..errors import InvalidInput
from ..models import Asset, ProfileResult
from ..safety import Budget
from ..scope import ScopePolicy


def analyze(asset: Asset, path: Path | None, output: Path, scope: ScopePolicy, budget: Budget) -> ProfileResult:
    if asset.kind in ("web", "api"):
        from .web_api import analyze as selected
    elif asset.kind in ("android", "apple"):
        from .mobile import analyze as selected
    elif asset.kind == "binary":
        from .binary import analyze as selected
    elif asset.kind in ("source", "firmware"):
        from .source_firmware import analyze as selected
    elif asset.kind == "container":
        from .container import analyze as selected
    elif asset.kind == "traffic":
        from .traffic import analyze as selected
    elif asset.kind in ("device", "ai", "contract"):
        from .special import analyze as selected
    else:
        raise InvalidInput(f"Profile unavailable: {asset.kind}")
    return selected(asset, path, output, scope, budget)
