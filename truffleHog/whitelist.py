import yaml
import hashlib

class WhitelistEntry(yaml.YAMLObject):
    def __init__(
        self, branch, commit, commitHash, date, path, reason, string, acknowledged=False
    ):
        self.branch = branch
        self.commit = commit
        self.commitHash = commitHash
        self.date = date
        self.path = path
        self.reason = reason
        self.string_detected = string
        self.acknowledged = acknowledged

        self.secret_guid = str(
            hashlib.md5(
                (commitHash + str(path) + string).encode("utf-8")
            ).hexdigest()
        )

    yaml_tag = "!WhitelistEntry"
    
    def __repr__(self):
        return f"{self.secret_guid} {self.string_detected}"

    def __eq__(self, other):
        return int(self.secret_guid == other.secret_guid)

    def __hash__(self):
        return int(self.secret_guid, 16)

def curate_whitelist(output):
    whitelist_in_memory = read_whitelist_to_memory()
    if not whitelist_in_memory:
        write_whitelist_to_disk(output)    
    else:
        whitelist_in_memory = prune_whitelist(output, whitelist_in_memory)

        for entry in output:
            whitelist = add_to_whitelist(entry, whitelist_in_memory)

        write_whitelist_to_disk(whitelist_in_memory)

def write_whitelist_to_disk(whitelist_object):
    try:
        with open("whitelist.yml", "w+") as whitelist:
            yaml.dump(whitelist_object, whitelist, encoding="utf-8")
    except Exception as e:
        print(f"Unable to write to whitelist: {e}")


def read_whitelist_to_memory():
    try:
        with open("whitelist.yml", "r") as whitelist:
            file_contents = yaml.load(whitelist, Loader=yaml.FullLoader)
        return file_contents
    except FileNotFoundError:
        return False

def add_to_whitelist(entry, whitelist):
    if entry not in whitelist:
        whitelist.append(entry)
        print(entry.secret_guid)    
    return whitelist   

def prune_whitelist(matches, whitelist):
    for entry in whitelist:
        if entry not in matches:
            print(f"Can no longer find {entry.secret_guid}")
            whitelist.remove(entry)
    return whitelist
