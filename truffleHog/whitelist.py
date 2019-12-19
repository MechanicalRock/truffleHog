import json
import hashlib
import jsons
from collections import Counter
from termcolor import colored
import colorama

colorama.init()


class WhitelistEntry:
    def __init__(
        self,
        branch,
        commit,
        commitHash,
        date,
        path,
        reason,
        stringDetected,
        acknowledged=False,
        secret_guid=None,
    ):
        self.branch = branch
        self.commit = commit
        self.commitHash = commitHash
        self.date = date
        self.path = path
        self.reason = reason
        self.stringDetected = stringDetected.lstrip("+-")
        self.acknowledged = acknowledged

        self.secret_guid = secret_guid
        if secret_guid == None:
            self.secret_guid = str(
                hashlib.md5(
                    (commitHash + str(path) + stringDetected).encode("utf-8")
                ).hexdigest()
            )

    def __repr__(self):
        return f"Secret Instance GUID: {self.secret_guid}, String Detected:{self.stringDetected}"

    def __eq__(self, other):
        return self.secret_guid == other.secret_guid

    def __hash__(self):
        return int(self.secret_guid, 16)


class WhitelistStatistics:
    def __init__(self, whitelist_object, pipeline_mode):
        self.whitelist_object = {
            entry for entry in whitelist_object if entry.acknowledged == False
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


def curate_whitelist(outstanding_secrets):
    whitelist_in_memory = read_whitelist_to_memory()
    if not whitelist_in_memory:
        print(f"Creating a new whitelist.json...")
        write_whitelist_to_disk(outstanding_secrets)
    else:
        outstanding_secrets, whitelist_in_memory = reconcile_secrets(
            outstanding_secrets, whitelist_in_memory
        )

        for entry in outstanding_secrets:
            whitelist = add_to_whitelist(entry, whitelist_in_memory)

        write_whitelist_to_disk(whitelist_in_memory)

    return outstanding_secrets


def write_whitelist_to_disk(whitelist_object):
    try:
        with open("whitelist.json", "w+") as whitelist:
            whitelist_object = jsons.dump(
                sorted(
                    whitelist_object,
                    key=lambda whitelist: whitelist.acknowledged,
                    reverse=False,
                )
            )
            json.dump(whitelist_object, whitelist, indent=4)
    except Exception as e:
        print(f"Unable to write to whitelist: {e}")


def read_whitelist_to_memory():
    try:
        with open("whitelist.json", "r") as whitelist:
            file_contents = json.load(whitelist)
            in_memory_whitelist = set()
            for entry in file_contents:
                in_memory_whitelist.add(WhitelistEntry(**entry))
        return in_memory_whitelist
    except Exception as e:
        print("Whitelist not found")
        return False


def add_to_whitelist(entry, whitelist):
    if entry not in whitelist:
        whitelist.add(entry)
    return whitelist


def reconcile_secrets(matches, whitelist):
    for entry in whitelist.copy():
        if entry not in matches:
            # print(f"Can no longer find {entry.secret_guid}")
            whitelist.remove(entry)
            continue
        if entry.acknowledged == True:
            # print(f"Already acknowledged:\n{entry}. No action required.")
            matches.remove(entry)
    return matches, whitelist


def remediate_secrets():
    in_memory_whitelist = read_whitelist_to_memory()
    if in_memory_whitelist:
        counter = Counter(
            [
                entry.stringDetected
                for entry in in_memory_whitelist
                if entry.acknowledged == False
            ]
        )
        for secret in counter:
            # if "PRIVATE KEY" in secret:
            #     # We can't automatically reconcile private keys
            #     continue
            classification = user_classify_secrets(secret)
            update_secret(secret, classification, in_memory_whitelist)
        write_whitelist_to_disk(in_memory_whitelist)
    else:
        return False


def user_classify_secrets(secret):
    secret = colored(secret, "yellow")
    while True:
        print()
        prompt = input(f"{secret}: False Positive? (y/n)> ")
        if prompt == "y":
            return True
        if prompt == "n":
            return False


def update_secret(secret, classification, whitelist):
    for entry in whitelist:
        if entry.stringDetected == secret:
            entry.acknowledged = classification


def whitelist_statistics(pipeline_mode=False):
    in_memory_whitelist = read_whitelist_to_memory()
    if in_memory_whitelist:
        unique_secrets = WhitelistStatistics(in_memory_whitelist, pipeline_mode)
        return unique_secrets
    else:
        return False
