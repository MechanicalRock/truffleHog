import unittest
import os
import sys
import json
import io
import re
import argparse
from collections import namedtuple
from unittest.mock import patch, MagicMock
from truffleHog.truffleHog import (
    find_strings,
    shannon_entropy,
    BASE64_CHARS,
    HEX_CHARS,
    _clone_git_repo,
)
from truffleHog.cli import cli as mechtrufflehog

from truffleHog.whitelist import (
    WhitelistEntry,
    write_whitelist_to_disk
)


class TestStringMethods(unittest.TestCase):
    MockedWhitelistUnacknowledged = WhitelistEntry(
        commit="fixing unicode commit message problem",
        commitAuthor="flower@flowers-MacBook-Pro.local",
        commitHash="7147cc7525c27d459152548e3284e03a73688907",
        confidence="Low",
        date="2016-12-31 23:15:08",
        path="truffleHog.py",
        reason="High Entropy",
        secretGuid="5beef298005122c34d8bab7abd1ef842",
        stringDetected="1234567890abcdefABCDEF"
    )

    MockedWhitelistAcknowledged = WhitelistEntry(
        commit="fixing unicode commit message problem",
        commitAuthor="flower@flowers-MacBook-Pro.local",
        commitHash="7147cc7525c27d459152548e3284e03a73688907",
        confidence="Low",
        date="2016-12-31 23:15:08",
        path="truffleHog.py",
        reason="High Entropy",
        secretGuid="5beef298005122c34d8bab7abd1ef842",
        stringDetected="1234567890abcdefABCDEF"
    )
    MockedWhitelistAcknowledged.acknowledged = True

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

    @patch('json.dump', return_value=None)
    def test_write_whitelist_to_disk(self, *args,):
        write_whitelist_to_disk([self.MockedWhitelistUnacknowledged])
        args[0].assert_called_once()

    @patch("truffleHog.truffleHog._clone_git_repo")
    @patch("truffleHog.truffleHog.Repo")
    @patch("shutil.rmtree")
    def test_repo_path(self, rmtree_mock, repo_const_mock, _clone_git_repo):
        find_strings("test_repo", repo_path="test/path/")
        rmtree_mock.assert_not_called()
        _clone_git_repo.assert_not_called()

    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[MockedWhitelistUnacknowledged])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=None))
    @patch('truffleHog.truffleHog.find_strings', return_value=[MockedWhitelistUnacknowledged])
    def test_basic_console_mode_fail(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        self.assertEqual(context.exception.code, 1)
    
    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[MockedWhitelistAcknowledged])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=None))
    @patch('truffleHog.truffleHog.find_strings', return_value=[MockedWhitelistAcknowledged])
    def test_basic_console_mode_pass_with_no_findings(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        self.assertEqual(context.exception.code, 0)
    
    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=None))
    @patch('truffleHog.truffleHog.find_strings', return_value=[])
    def test_basic_console_mode_pass_with_findings(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        self.assertEqual(context.exception.code, 0)

    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[MockedWhitelistUnacknowledged])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=True, block=True))
    @patch('truffleHog.truffleHog.find_strings', return_value=[MockedWhitelistUnacknowledged])
    def test_basic_pipeline_mode_fail(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        self.assertEqual(context.exception.code, 1)
    
    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[MockedWhitelistAcknowledged])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=True, block=True))
    @patch('truffleHog.truffleHog.find_strings', return_value=[MockedWhitelistAcknowledged])
    def test_basic_pipeline_mode_pass_with_no_findings(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        self.assertEqual(context.exception.code, 0)
    
    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=True, block=True))
    @patch('truffleHog.truffleHog.find_strings', return_value=[])
    def test_basic_pipeline_mode_pass_with_no_findings(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        self.assertEqual(context.exception.code, 0)
    
    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[MockedWhitelistAcknowledged])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=True, block=True))
    @patch('truffleHog.truffleHog.find_strings', return_value=[MockedWhitelistAcknowledged])
    def test_pipeline_mode_with_ack_findings_doesnt_write_to_disk_but_reads_from_disk(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        #writewhitelist_to_disk
        args[2].assert_not_called()
        args[3].assert_not_called()
        args[0].assert_called_once()

    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[MockedWhitelistUnacknowledged])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=True, block=True))
    @patch('truffleHog.truffleHog.find_strings', return_value=[MockedWhitelistUnacknowledged])
    def test_pipeline_mode_with_unack_findings_doesnt_write_to_disk_but_reads_from_disk(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        #writewhitelist_to_disk
        args[2].assert_not_called()
        args[3].assert_not_called()
        args[0].assert_called_once()

    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=True, block=True))
    @patch('truffleHog.truffleHog.find_strings', return_value=[])
    def test_pipeline_mode_with_no_findings_doesnt_write_to_disk_and_doesnt_read_from_disk(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        #writewhitelist_to_disk
        args[2].assert_not_called()
        args[3].assert_not_called()
        args[0].assert_called_once()


    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[MockedWhitelistAcknowledged])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=False, block=True))
    @patch('truffleHog.truffleHog.find_strings', return_value=[MockedWhitelistAcknowledged])
    def test_console_mode_with_ack_findings_does_write_to_disk_and_does_read(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        #writewhitelist_to_disk
        args[2].assert_called_once()
        args[3].assert_called()
        args[0].assert_called_once()

    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[MockedWhitelistUnacknowledged])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=False, block=True))
    @patch('truffleHog.truffleHog.find_strings', return_value=[MockedWhitelistUnacknowledged])
    def test_console_mode_with_unack_findings_does_write_to_disk_and_does_read(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        #writewhitelist_to_disk
        args[2].assert_called_once()
        args[3].assert_called()
        args[0].assert_called_once()

    @patch('truffleHog.whitelist.read_whitelist_to_memory', return_value=[])
    @patch('truffleHog.whitelist.write_whitelist_to_disk', return_value=None)
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(repo_path=None, git_url=None, remediate=None, commit=None, pipeline_mode=False, block=True))
    @patch('truffleHog.truffleHog.find_strings', return_value=[])
    def test_console_mode_with_no_findings_doesnt_write_to_disk_and_doesnt_read_from_disk(self, *args):
        with self.assertRaises(SystemExit) as context:
            mechtrufflehog()
        #writewhitelist_to_disk
        args[2].assert_not_called()
        args[3].assert_not_called()
        args[0].assert_called_once()


if __name__ == "__main__":
    unittest.main()
