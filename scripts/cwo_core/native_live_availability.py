"""Independent, default-off holds for native model effects.

These are installed source decisions, never plan, environment or CLI inputs.
Offline fixtures patch only the required decisions while replacing all model
and process effects. Restoration still requires the operator's separate review.
"""

N1_LIVE_AVAILABLE = False
POOL_LIVE_AVAILABLE = False
CAMPAIGN_LIVE_AVAILABLE = False


class NativeLiveUnavailable(RuntimeError):
    """A native route is held before claims, writes or process launch."""


def require_n1_live() -> None:
    if N1_LIVE_AVAILABLE is not True:
        raise NativeLiveUnavailable("native-n1-live-unavailable")


def require_pool_live() -> None:
    if POOL_LIVE_AVAILABLE is not True:
        raise NativeLiveUnavailable("native-pool-live-unavailable")


def require_campaign_live() -> None:
    if CAMPAIGN_LIVE_AVAILABLE is not True:
        raise NativeLiveUnavailable("native-campaign-live-unavailable")


def require_v8_live_routes(plan) -> None:
    require_n1_live()
    if len(plan['children']) > 1:
        require_pool_live()


def require_activation_live(profile: str | None = None) -> None:
    """Require N1 before plan reads, then the selected profile's pool decision."""
    require_n1_live()
    if profile is None:
        return
    if profile == "n2-read-only":
        require_pool_live()
    elif profile not in {"n1-read-only", "n1-mutable"}:
        raise NativeLiveUnavailable("native-activation-profile-unavailable")
