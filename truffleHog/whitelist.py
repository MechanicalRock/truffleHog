import sys
import json
import hashlib
import jsons
import datetime
from itertools import groupby
from collections import Counter
from termcolor import colored
import colorama
from enum import Enum

colorama.init()


class Classifications:
    valid = ["FALSE_POSITIVE", "REMEDIATED"]




class ScanResults:
    def __init__(self, **kwargs):
        self.possible_secrets = set()
        self.known_secrets = {
            result
            for result in ScanResults.read_whitelist_from_disk()
            if result.is_acknowledged() == True
        }
        self.reconciled_results = set()

    def reconcile_secrets(self):
        self.reconciled_results = self.known_secrets.union(self.possible_secrets)
        self.possible_secrets = self.possible_secrets.difference_update(
            self.known_secrets
        )
        if self.possible_secrets == None:
            self.possible_secrets = set()

    @staticmethod
    def write_whitelist_to_disk(scan_results):
        try:
            with open("whitelist.json", "w+") as whitelist:
                results = jsons.dump(
                    sorted(
                        scan_results,
                        key=lambda whitelist: whitelist.classification,
                        reverse=True,
                    )
                )
                json.dump(results, whitelist, indent=4)
        except Exception as e:
            print(f"Unable to write to whitelist: {e}", file=sys.stderr)

    @staticmethod
    def read_whitelist_from_disk():
        try:
            with open("whitelist.json", "r") as whitelist:
                file_contents = json.load(whitelist)
                known_secrets = set()
                for entry in file_contents:
                    known_secrets.add(WhitelistEntry(**entry))
                return known_secrets
        except Exception as e:
            print(f"Whitelist not found: {e}", file=sys.stderr)
            return set()


class WhitelistEntry:
    def __init__(
        self,
        commit,
        commitAuthor,
        commitHash,
        date,
        path,
        reason,
        stringDetected,
        acknowledged=False,
        secretGuid=None,
        confidence="High",
        classification="UNCLASSIFIED",
    ):
        self.commit = commit
        self.commitAuthor = commitAuthor
        self.commitHash = commitHash
        self.date = date
        self.path = path
        self.reason = reason
        self.stringDetected = stringDetected.lstrip("+-")

        self.secretGuid = secretGuid
        if secretGuid == None:
            self.secretGuid = str(
                hashlib.md5(
                    (commitHash + str(path) + stringDetected).encode("utf-8")
                ).hexdigest()
            )
        self.confidence = confidence
        if self.reason == "High Entropy":
            self.confidence = "Low"

        self.classification = WhitelistEntry.classify(classification)

    @staticmethod
    def classify(string):
        if string in Classifications.valid:
            return string
        else:
            return "UNCLASSIFIED"

    def is_acknowledged(self):
        if self.classification in Classifications.valid:
            return True
        return False

    def __repr__(self):
        return f"Secret Instance GUID: {self.secretGuid}, String Detected:{self.stringDetected}"

    def __eq__(self, other):
        return self.secretGuid == other.secretGuid

    def __hash__(self):
        return int(self.secretGuid, 16)


class WhitelistStatistics:
    def __init__(self, whitelist_object, pipeline_mode):
        self.whitelist_object = {
            entry for entry in whitelist_object if not entry.is_acknowledged()
        }

        self.pipeline_mode = pipeline_mode

    def top_secrets(self):
        if self.pipeline_mode == True:
            return "Secrets unavailable in pipeline mode."
        counter = Counter([entry.stringDetected for entry in self.whitelist_object])
        top_secrets = ""
        for key, val in counter.most_common(10):
            top_secrets += f"{'  '+key:<35}{val:>7}\n"
        return top_secrets

    def largest_files(self):
        largest_files = ""
        counter = Counter([entry.path for entry in self.whitelist_object])

        for key, val in counter.most_common(10):
            largest_files += f"{'  '+key:<35}{val:>7}\n"
        return largest_files

    def unique(self, attr):
        return set([getattr(entry, attr) for entry in self.whitelist_object])

    def count(self, attr):
        return len([getattr(entry, attr) for entry in self.whitelist_object])

    def breakdown(self):
        reason_breakdown = ""
        for given_reason in self.unique("reason"):
            reason_breakdown += f"{'  '+given_reason:<35}{len([x for x in self.whitelist_object if x.reason == given_reason]):>7}\n"
        return reason_breakdown

    def to_dict(self):
        return {
            "Files": len(self.unique("path")),
            "Total Strings": self.count("stringDetected"),
            "Unique Strings": len(self.unique("stringDetected")),
            "Categories": " ".join(self.breakdown().replace("\n", ",").split()),
            "Top Files": " ".join(self.largest_files().replace("\n", ",").split()),
        }

    def to_dict_per_commit(self, repo, commit):
        now = datetime.datetime.utcnow()
        commit = repo.commit(commit)
        commit_timestamp = datetime.datetime.utcfromtimestamp(commit.authored_date)
        return {
            "detectionTimestamp": now.strftime("%Y-%m-%dT%H:%M:%S")
            + now.strftime(".%f")[:4]
            + "Z",
            "repository": commit.repo.git_dir,
            "commit": commit.hexsha,
            "commitMessage": commit.message.strip("\n"),
            "commitTimestamp": commit_timestamp.strftime("%Y-%m-%dT%H:%M:%S")
            + commit_timestamp.strftime(".%f")[:4]
            + "Z",
            "totalStrings": self.count("stringDetected"),
            "uniqueStrings": len(self.unique("stringDetected")),
            "findings": jsons.dump(self.whitelist_object),
        }

    def __repr__(self):
        message = (
            f"Whitelist Statistics:\n"
            f"{'  Files: ':<35}{len(self.unique('path')):>7}\n"
            f"{'  Total Strings: ':<35}{self.count('stringDetected'):>7}\n"
            f"{'  Unique Strings: ':<35}{len(self.unique('stringDetected')):>7}\n"
            f"\nCategories:\n"
            f"{self.breakdown()}"
            f"\nTop Files:\n"
            f"{self.largest_files()}\n"
            f"\nMost Common Secrets:\n"
            f"{self.top_secrets()}\n"
        )
        return message


class Remediation:
    @staticmethod
    def remediate_secrets():
        print(colored(f"Valid Classifications: (U)nclassified, (R)emediated, (F)alse Positive.", "green"))
        print(colored(f"(F)alse Positives: the category for items that are definitely not secrets.", "green"))
        print(colored(f"(R)emediated: the category for items are actually secrets and have been actioned appropriately.", "green"))
        print(colored(f"(U)ncategoried: the category for any outstanding item awaiting classification or action.", "green"))
        input("Press Any Key > ")
        scan = ScanResults()
        in_memory_whitelist = scan.read_whitelist_from_disk()

        if in_memory_whitelist:
            counter = Counter(
                [
                    (entry.stringDetected, entry.commitHash)
                    for entry in in_memory_whitelist
                    if entry.is_acknowledged() == False
                ]
            )
            for secret in counter:
                classification = Remediation.user_classify_secrets(*secret)
                if classification == 'break':
                    break
                Remediation.update_secret(secret[0], classification, in_memory_whitelist)

            ScanResults.write_whitelist_to_disk(in_memory_whitelist)

    @staticmethod
    def user_classify_secrets(secret, commitHash):
        secret = colored(secret, "yellow")
        commitHash = colored(commitHash, "yellow")

        while True:
            print()
            print(f"String Detected={secret} in SHA:{commitHash}:")
            print(colored(f"Valid Classifications: (U)nclassified, (R)emediated, (F)alse Positive. (S)top.", "green"))
            prompt = input(
                f""
            )
            if prompt in "uU":
                return "UNCLASSIFIED"
            if prompt in "rR":
                return "REMEDIATED"
            if prompt in "fF":
                return "FALSE_POSITIVE"
            if prompt in "sS":
                return "break"

    @staticmethod
    def update_secret(secret, classification, whitelist):
        for entry in whitelist:
            if entry.stringDetected == secret:
                entry.classification = classification
