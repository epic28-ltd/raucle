"""Deprecated compatibility shim: ``raucle_detect`` is now ``raucle``.

The package was renamed in v0.22.0. This shim keeps existing code working
(``import raucle_detect`` and ``from raucle_detect.scanner import ...``) by
aliasing the old names to the new package. Submodules resolve to the SAME
module objects as their ``raucle.*`` counterparts, so mixed old/new imports
share class identity.

Removal schedule (house deprecation convention, named up front): the shim
will be removed in v0.26.0. Until then ``import raucle_detect`` keeps
working with this DeprecationWarning; from v0.26.0 it raises ImportError
and the module no longer exists. Migrate imports to ``raucle`` now.
"""

import importlib
import importlib.abc
import importlib.util
import sys
import warnings

import raucle as _raucle

warnings.warn(
    "the 'raucle_detect' package has been renamed to 'raucle'; "
    "update imports now (this shim will be removed in v0.26.0)",
    DeprecationWarning,
    stacklevel=2,
)

_OLD = "raucle_detect"
_NEW = "raucle"


class _AliasLoader(importlib.abc.Loader):
    """Loader that returns the already-imported ``raucle`` module object."""

    def __init__(self, module):
        self._module = module

    def create_module(self, spec):
        return self._module

    def exec_module(self, module):
        pass  # already executed under its canonical name


class _AliasFinder(importlib.abc.MetaPathFinder):
    """Resolve ``raucle_detect.X`` to the SAME object as ``raucle.X``."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname != _OLD and not fullname.startswith(_OLD + "."):
            return None
        real_name = _NEW + fullname[len(_OLD) :]
        module = importlib.import_module(real_name)
        return importlib.util.spec_from_loader(fullname, _AliasLoader(module))


if not any(isinstance(f, _AliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _AliasFinder())

# The bare old name is the new package itself.
sys.modules[_OLD] = _raucle
