"""Check registry for the Sentinel Agent.

Check mixin modules (security, storage, kernel, system, services) decorate their
top-level check methods with @register_check(order). SentinelAgent.run_loop then
iterates registered_check_names() instead of a hand-maintained list, so adding a
check is a one-line decorator, not an edit in three places.
"""

CHECK_REGISTRY = []


def register_check(order):
    """Register a check method to run in run_loop at the given order position."""
    def decorator(func):
        CHECK_REGISTRY.append((order, func.__name__))
        return func
    return decorator


def registered_check_names():
    """Check method names sorted by their registered order."""
    return [name for _, name in sorted(CHECK_REGISTRY)]
