# Import _docker_compat first to monkey-patch DockerSandboxEnvironment.exec
# for Windows containers BEFORE any task or sandbox is created.
from . import _docker_compat  # noqa: F401
from .task import sysrepair_bench

__all__ = ["sysrepair_bench"]
