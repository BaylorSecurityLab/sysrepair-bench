# Import compat modules FIRST — they monkey-patch inspect_ai before any task
# or sandbox is created. Order matters: _inspect_compat patches the cancel/
# shield bugs at the inspect_ai layer, _docker_compat patches the Windows
# exec layer on top. Both are import-side-effect modules.
from . import _inspect_compat  # noqa: F401  shield log_sample / compose_down / faster kill
from . import _docker_compat   # noqa: F401  Windows DockerSandboxEnvironment.exec
from .task import sysrepair_bench

__all__ = ["sysrepair_bench"]
