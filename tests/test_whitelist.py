import os

import unittest
import pytest
import argparse
from unittest.mock import patch, MagicMock

from truffleHog.whitelistExamples import (
    MockedWhitelistUnacknowledged,
    MockedWhitelistAcknowledged,
)

from truffleHog.whitelist import WhitelistEntry, WhitelistStatistics, ScanResults

def whitelist_object():
    # Remember some of these whitelist entries are duplicates by virtue of the fact that their secretGuids are equivalent
    return [
            WhitelistEntry(
                commit="fixing unicode commit message problem",
                commitAuthor="flower@flowers-MacBook-Pro.local",
                commitHash="7147cc7525c27d459154438e3284e03a73688907",
                confidence="Low",
                date="2016-12-31 23:15:08",
                path="truffleHog.py",
                reason="High Entropy",
                secretGuid="5beef298005122c34d8bab7abd1ef842",
                stringDetected="1234567890abcdefABCDEF",
            ),
            WhitelistEntry(
                commit="fixing unicode commit message problem",
                commitAuthor="flower@flowers-MacBook-Pro.local",
                commitHash="7147cc7525c27d459152548e3284e03a73688907",
                confidence="Low",
                date="2016-12-31 23:15:08",
                path="truffleHog.py",
                reason="High Entropy",
                secretGuid="5beef298005122c34d8bab7abd1ef842",
                stringDetected="1234567890abcdefABCDEF",
            ),
            WhitelistEntry(
                commit="fixing unicode commit message problem",
                commitAuthor="flower@flowers-MacBook-Pro.local",
                commitHash="7147cc7525c27d459152548e3284e03a73688907",
                confidence="Low",
                date="2016-12-31 23:15:08",
                path="truffleHog.py",
                reason="High Entropy",
                secretGuid="5beef298005122c5beef29800abd1ef842",
                stringDetected="1234567890abcdefABCDEF",
            )
        ]

class TestStringMethods(unittest.TestCase):
    @patch("truffleHog.truffleHog.ScanResults.read_whitelist_from_disk", return_value=[])
    def test_ScanResults_can_be_instantiated(self, patch):
        scan = ScanResults()
        scan.known_secrets = set()
        scan.possible_secrets = set(whitelist_object())

        assert len(scan.possible_secrets) == 2
        assert len(scan.known_secrets) == 0
        assert len(scan.reconciled_results) == 0

    def test_ScanResults_can_write_to_disk_with_no_results(self):
        scan = ScanResults()
        scan.known_secrets = set()
        scan.possible_secrets = set(whitelist_object())
        scan.reconcile_secrets()
        scan.write_whitelist_to_disk(scan.reconciled_results)
        assert len(scan.read_whitelist_from_disk()) == 2
        assert len({secret for secret in scan.reconciled_results if secret.is_acknowledged() == True}) == 0
        assert len({secret for secret in scan.reconciled_results if secret.is_acknowledged() == False}) == 2
    
    def test_ScanResults_can_write_to_disk_with_some_acknowledged_results(self):
        scan = ScanResults()
        scan.known_secrets = set()
        scan.possible_secrets = set(whitelist_object())
        wle = WhitelistEntry(
                commit="fixing unicode commit message problem",
                commitAuthor="flower@flowers-MacBook-Pro.local",
                commitHash="7147cc7525c27d459152548e3284e03a73688907",
                confidence="Low",
                date="2016-12-31 23:15:08",
                path="truffleHog.py",
                reason="High Entropy",
                secretGuid="5beef298005122c34d8bab7abd1ef842",
                stringDetected="1234567890abcdefABCDEF",
                classification="FALSE_POSITIVE"
            )
        scan.known_secrets = set([wle])
        scan.reconcile_secrets()
        scan.write_whitelist_to_disk(scan.reconciled_results)
        assert len(scan.read_whitelist_from_disk()) == 2
        assert scan.possible_secrets == set()
        assert len(scan.reconciled_results) == 2
        assert len({secret for secret in scan.reconciled_results if secret.is_acknowledged() == True}) == 1
        assert len({secret for secret in scan.reconciled_results if secret.is_acknowledged() == False}) == 1

    def test_WhitelistEntry(self):
        entries = whitelist_object()
        assert len([wle for wle in entries if wle.stringDetected == "1234567890abcdefABCDEF"]) == 3
    
    def test_WhitelistEntry_with_same_guid_are_equal(self):
        entries = whitelist_object()
        assert entries[0] == entries[1]
        assert entries [1] != entries[2]

    def test_WhitelistEntry_acknowledged_if_not_uncategoried(self):
        pass 

    def test_WhitelistStatisticsin_pipeline_mode(self):
        wls = WhitelistStatistics(whitelist_object(), pipeline_mode=True)
        print(wls)
        assert len(wls.whitelist_object) == 2
        assert len(wls.unique("stringDetected")) == 1
        assert "1234567890abcdefABCDEF" not in wls.__repr__()

    def test_WhitelistStatistics_in_console_mode(self):
        wls = WhitelistStatistics(whitelist_object(), pipeline_mode=False)
        print(wls)
        assert len(wls.whitelist_object) == 2
        assert len(wls.unique("stringDetected")) == 1
        assert "1234567890abcdefABCDEF" in wls.__repr__()
    
    def test_WhitelistStatistics_test_methods(self):
        wls = WhitelistStatistics(whitelist_object(), pipeline_mode=False)
        print(wls)
        assert type(wls.to_dict()) == dict
        assert wls.to_dict()["Total Strings"] == 2
        assert wls.to_dict()["Unique Strings"] == 1