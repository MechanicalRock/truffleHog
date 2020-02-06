#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from math import log
import datetime
import argparse
import hashlib
import tempfile
import os
import json
import re
import stat
from git import Repo
from git import NULL_TREE
from truffleHog.whitelist import WhitelistEntry, WhitelistStatistics, ScanResults, Remediation
from termcolor import colored

import colorama

colorama.init()

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


def _get_regexes():
    with open(os.path.join(os.path.dirname(__file__), "regexes.json"), "r") as f:
        regexes = json.loads(f.read())

    for key in regexes:
        regexes[key] = re.compile(regexes[key])

    return regexes


def _exclusion_filter(path):
    excluded_files = ["whitelist.json", "package-lock.json"]
    for file_seg in excluded_files:
        if file_seg in path:
            return True
    return False


def _get_repo(repo_path):
    try:
        try:
            repo = Repo(repo_path)
        except:
            repo = Repo(_clone_git_repo(repo_path))
    except Exception as e:
        print(
            colored(
                f"Unable to find a git repository. Are you sure {e} is a valid git repository?",
                "red",
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        repo.iter_commits()
        return repo
    except ValueError as e:
        print(
            colored(
                f"Can't operate on this repository. Is it a non-empty git repository? {e}.",
                "red",
            ),
            file=sys.stderr,
        )
        sys.exit(1)




def _clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path


def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += -p_x * log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = set()
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.add(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.add(letters)
    return strings


def entropicDiff(printableDiff, commit_time, prev_commit, path, commitHash):
    entropicFindings = set()
    stringsFound = set()
    lines = printableDiff.split("\n")
    for line in lines:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    stringsFound.add(string)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    stringsFound.add(string)
    for string in stringsFound:
        entropicFindings.add(
            WhitelistEntry(
                commit=prev_commit.message.replace("\n", ""),
                commitAuthor=prev_commit.author.email,
                commitHash=prev_commit.hexsha,
                date=commit_time,
                path=path,
                reason="High Entropy",
                stringDetected=string,
            )
        )

    return entropicFindings


def regex_check(printableDiff, commit_time, prev_commit, path, commitHash):
    regex_matches = set()
    regexes = _get_regexes()
    for key in regexes:
        found_strings = regexes[key].findall(printableDiff, re.MULTILINE)

        for string in found_strings:
            regex_matches.add(
                WhitelistEntry(
                    commit=prev_commit.message.replace("\n", ""),
                    commitAuthor=prev_commit.author.email,
                    commitHash=prev_commit.hexsha,
                    date=commit_time,
                    path=path,
                    reason=key,
                    stringDetected=string,
                )
            )
    return regex_matches


def diff_worker(diff, curr_commit, prev_commit, commitHash):
    issues = set()
    for blob in diff:
        path = blob.b_path if blob.b_path else blob.a_path
        if _exclusion_filter(path):
            continue
        printableDiff = blob.diff.decode("utf-8", errors="replace")
        if printableDiff.startswith("Binary files"):
            continue
        commit_time = datetime.datetime.fromtimestamp(
            prev_commit.committed_date
        ).strftime("%Y-%m-%d %H:%M:%S")

        entropic_results = entropicDiff(
            printableDiff, commit_time, curr_commit, path, commitHash
        )

        found_regexes = regex_check(
            printableDiff, commit_time, curr_commit, path, commitHash
        )
        issues = issues.union(found_regexes)
        issues = issues.union(entropic_results)

    return issues


def scan_commit(commit, repo):
    curr_commit = repo.commit(commit)
    try:
        prev_commit = curr_commit.parents[0]
    except:
        prev_commit = curr_commit

    commitHash = curr_commit.hexsha
    diff = prev_commit.diff(curr_commit, create_patch=True)

    diff = [blob for blob in diff.iter_change_type("M")] + [
        blob for blob in diff.iter_change_type("A")
    ]
    commit_results = diff_worker(diff, curr_commit, prev_commit, commitHash)

    return commit_results


def find_strings(repo_path, commit=None):
    output = set()
    repo = _get_repo(repo_path)
    commits = repo.iter_commits()

    if commit:
        try:
            repo.commit(commit)
        except:
            print(colored(f"Could not find {commit}", color="red"), file=sys.stderr),
            sys.exit(0)

        commits = [commit]

    for commit in commits:
        commit_diff = scan_commit(commit, repo)
        output = output.union(commit_diff)
    return output


def console_mode(args):
    scan = ScanResults()

    failure_message = None
    repo = _get_repo(repo_path=args.repo_path)

    scan.possible_secrets = find_strings(repo_path=args.repo_path, commit=args.commit)
    print(
        colored(f"Working with project path {repo.git_dir}", "green"), file=sys.stderr
    )

    scan.reconcile_secrets()
    wls = WhitelistStatistics(scan.reconciled_results, args.pipeline_mode)
    print(colored(wls, "green"))
    scan.write_whitelist_to_disk(scan.reconciled_results)

    return wls


def pipeline_mode(args):
    scan = ScanResults()

    repo = _get_repo(repo_path=args.repo_path)

    scan.possible_secrets = find_strings(repo_path=args.repo_path, commit=args.commit)

    wls = WhitelistStatistics(scan.possible_secrets, pipeline_mode=True)

    if args.commit:
        results = json.dumps(wls.to_dict_per_commit(repo, args.commit))
    else:
        results = json.dumps(wls.to_dict())

    print(results)
    return wls


def exit_code(output, pipeline_mode=False):
    if pipeline_mode:
        sys.exit(0)
    if output:
        print(
            colored(
                f"Secrets detected: {len(output)}. Please review the output in whitelist.json and either acknowledge the secrets or remediate them",
                "red",
            )
        )
        sys.exit(1)
    else:
        print(
            colored(
                "Detected no secrets! Clear to commit whitelist.json and push to remote repository",
                "green",
            )
        )
        sys.exit(0)


def main(*args, **kwargs):
    parser = argparse.ArgumentParser(
        description="Find secrets hidden in the depths of git."
    )

    parser.add_argument(
        "--repo_path", type=str, default=".", help="File path to git project "
    )
    parser.add_argument("--commit", type=str, help="Commit SHA of git commit to scan")
    parser.add_argument(
        "--remediate",
        help="Interactive mode for reconciling secrets",
        action="store_true",
    )

    parser.add_argument(
        "--pipeline_mode",
        help="Flags that secrets should not be output and that results are directed to stderr.",
        action="store_true",
    )

    args = parser.parse_args()

    if args.remediate:
        Remediation.remediate_secrets()
        sys.exit(0)

    if args.pipeline_mode:
        pipeline_mode(args)
        exit_code(wls.whitelist_object, pipeline_mode=True)

    if not args.pipeline_mode:
        wls = console_mode(args)
        exit_code(wls.whitelist_object)


if __name__ == "__main__":
    main()
