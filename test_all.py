import unittest
import os
import sys
import json
import io
import re
from collections import namedtuple
from unittest.mock import patch, MagicMock
from truffleHog.truffleHog import (
    find_strings,
    shannon_entropy,
    BASE64_CHARS,
    HEX_CHARS,
    _clone_git_repo,
)


class TestStringMethods(unittest.TestCase):
    def test_shannon(self):
        random_stringB64 = (
            "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
        )
        random_stringHex = "b3A0a1FDfe86dcCE945B72"
        self.assertGreater(shannon_entropy(random_stringB64, BASE64_CHARS), 4.5)
        self.assertGreater(shannon_entropy(random_stringHex, HEX_CHARS), 3)

    def test_cloning(self):
        project_path = _clone_git_repo("https://github.com/dxa4481/truffleHog.git")
        license_file = os.path.join(project_path, "LICENSE")
        self.assertTrue(os.path.isfile(license_file))

    def test_unicode_expection(self):
        try:
            find_strings("https://github.com/dxa4481/tst.git")
        except UnicodeEncodeError:
            self.fail("Unicode print error")

    def test_return_correct_commit(self):
        # Start at commit d15627104d07846ac2914a976e8e347a663bbd9b, which
        # is immediately followed by a secret inserting commit:
        # https://github.com/dxa4481/truffleHog/commit/9ed54617547cfca783e0f81f8dc5c927e3d1e345
        commit_w_secret = "d15627104d07846ac2914a976e8e347a663bbd9b"
        cross_validating_commit_w_secret_comment = "Oh no a secret file"

        results = find_strings(
            "https://github.com/dxa4481/truffleHog.git", commit=commit_w_secret
        )
        result = results.pop()
        self.assertEqual(cross_validating_commit_w_secret_comment, result.commit)
    
    def test_exit_if_invalid_commit(self):
        # Start at commit d15627104d07846ac2914a976e8e347a663bbd9b, which
        # is immediately followed by a secret inserting commit:
        # https://github.com/dxa4481/truffleHog/commit/9ed54617547cfca783e0f81f8dc5c927e3d1e345
        commit_w_secret = "14a976e8e347a663bbd9b"
        cross_validating_commit_w_secret_comment = "Oh no a secret file"

        with self.assertRaises(SystemExit) as context:
            find_strings(
            "https://github.com/dxa4481/truffleHog.git", commit=commit_w_secret
        )

        self.assertEqual(context.exception.code, 0)

    @patch("truffleHog.truffleHog._clone_git_repo")
    @patch("truffleHog.truffleHog.Repo")
    @patch("shutil.rmtree")
    def test_repo_path(self, rmtree_mock, repo_const_mock, _clone_git_repo):
        find_strings("test_repo", repo_path="test/path/")
        rmtree_mock.assert_not_called()
        _clone_git_repo.assert_not_called()


if __name__ == "__main__":
    unittest.main()
