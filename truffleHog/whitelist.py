import json
import hashlib
import jsons


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
        self.stringDetected = stringDetected
        self.acknowledged = acknowledged

        self.secret_guid = secret_guid
        if secret_guid == None:
            self.secret_guid = str(
                hashlib.md5(
                    (commitHash + str(path) + stringDetected).encode("utf-8")
                ).hexdigest()
            )

    def __repr__(self):
        return f"{self.secret_guid} {self.stringDetected}"

    def __eq__(self, other):
        return self.secret_guid == other.secret_guid

    def __hash__(self):
        return int(self.secret_guid, 16)


def curate_whitelist(outstanding_secrets):
    whitelist_in_memory = read_whitelist_to_memory()
    if not whitelist_in_memory:
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
            whitelist_object = jsons.dump(whitelist_object)
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
        print(f"Error opening whitelist: {e}")
        return False


def add_to_whitelist(entry, whitelist):
    if entry not in whitelist:
        whitelist.add(entry)
    return whitelist


def reconcile_secrets(matches, whitelist):
    for entry in whitelist.copy():
        if entry not in matches:
            print(f"Can no longer find {entry.secret_guid}")
            whitelist.remove(entry)
        if entry.acknowledged == True:
            print(entry)
            matches.remove(entry)
    return matches, whitelist