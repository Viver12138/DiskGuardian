import os
import unittest

from diskguardian.storage import db
from tests.support import cleanup, unique_dir


class StorageTests(unittest.TestCase):
    def setUp(self):
        self._previous = os.environ.get("LOCALAPPDATA")
        self._dir = unique_dir("store")
        os.environ["LOCALAPPDATA"] = str(self._dir)
        self.addCleanup(self._restore)

    def _restore(self):
        if self._previous is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = self._previous
        cleanup(self._dir)
