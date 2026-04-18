from fuse import Operations

from .fs_core import CoreOpsMixin
from .fs_directory_ops import DirectoryOpsMixin
from .fs_file_ops import FileOpsMixin


class FuseFS(CoreOpsMixin, DirectoryOpsMixin, FileOpsMixin, Operations):
    """Composed FUSE filesystem implementation.

    The class keeps a stable public API while implementation details are
    split across focused mixin modules.
    """

    pass
