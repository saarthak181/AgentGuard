"""AgentGuard deterministic policy and audit boundary."""

__all__ = ["AgentGuard", "ExecutionResult"]


def __getattr__(name):
    if name in __all__:
        from .guard import AgentGuard, ExecutionResult
        return {"AgentGuard": AgentGuard, "ExecutionResult": ExecutionResult}[name]
    raise AttributeError(name)
