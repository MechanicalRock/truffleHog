#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import sys
import math
import datetime
import argparse
import uuid
import hashlib
import tempfile
import os
import re
import json
import stat
import yaml
from git import Repo
from git import NULL_TREE
from truffleHogRegexes.regexChecks import regexes
from dataclasses import dataclass, field
from whitelist import WhitelistEntry, curate_whitelist
import cProfile


def main():
    parser = argparse.ArgumentParser(
        description="Find secrets hidden in the depths of git."
    )
    parser.add_argument(
        "--json", dest="output_json", action="store_true", help="Output in JSON"
    )
    parser.add_argument(
        "--regex",
        dest="do_regex",
        action="store_true",
        help="Enable high signal regex checks",
    )
    parser.add_argument("--entropy", dest="do_entropy", help="Enable entropy checks")
    parser.add_argument(
        "--since_commit", dest="since_commit", help="Only scan from a given commit hash"
    )
    parser.add_argument(
        "--max_depth",
        dest="max_depth",
        help="The max commit depth to go back when searching for secrets",
    )
    parser.add_argument(
        "--branch", dest="branch", help="Name of the branch to be scanned"
    )
    parser.add_argument(
        "--repo_path",
        type=str,
        dest="repo_path",
        help="Path to the cloned repo. If provided, git_url will not be used",
    )

    parser.add_argument("git_url", type=str, help="URL for secret searching")

    parser.set_defaults(regex=True)
    parser.set_defaults(max_depth=1000000)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(entropy=True)
    parser.set_defaults(branch=None)
    parser.set_defaults(repo_path=None)
    args = parser.parse_args()

    output = find_strings(
        args.git_url,
        args.since_commit,
        args.max_depth,
        args.output_json,
        args.do_regex,
        do_entropy,
        surpress_output=False,
        branch=args.branch,
        repo_path=args.repo_path,
    )

    curate_whitelist(output)


    if output:
        sys.exit(1)
    else:
        sys.exit(0)


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


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
            entropy += -p_x * math.log(p_x, 2)
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


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path




def do_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash):
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
                    printableDiff = printableDiff.replace(
                        string, bcolors.WARNING + string + bcolors.ENDC
                    )
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    stringsFound.add(string)
                    printableDiff = printableDiff.replace(
                        string, bcolors.WARNING + string + bcolors.ENDC
                    )
    for string in stringsFound:
        if len(stringsFound) > 0:
            entropicFindings.add(
                WhitelistEntry(
                    branch=branch_name,
                    commit=prev_commit.message.replace("\n", ""),
                    commitHash=prev_commit.hexsha,
                    date=commit_time,
                    path=blob.b_path if blob.b_path else blob.a_path,
                    reason="High Entropy",
                    string=string,
                )
            )
    return entropicFindings


def regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash):
    regex_matches = set()
    for key in regexes:
        found_strings = regexes[key].findall(printableDiff)

        for string in found_strings:
            regex_matches.add(
                WhitelistEntry(
                    branch=branch_name,
                    commit=prev_commit.message.replace("\n", ""),
                    commitHash=prev_commit.hexsha,
                    date=commit_time,
                    path=blob.b_path if blob.b_path else blob.a_path,
                    reason=key,
                    string=string,
                )
            )
    return regex_matches


def diff_worker(
    diff,
    curr_commit,
    prev_commit,
    branch_name,
    commitHash,
    custom_regexes,
    do_entropy,
    do_regex,
    printJson,
    surpress_output,
):
    issues = set()
    for blob in diff:
        printableDiff = blob.diff.decode("utf-8", errors="replace")
        if printableDiff.startswith("Binary files"):
            continue
        commit_time = datetime.datetime.fromtimestamp(
            prev_commit.committed_date
        ).strftime("%Y-%m-%d %H:%M:%S")

        foundIssues = set()
        entropicDiff = do_entropy(
            printableDiff, commit_time, branch_name, prev_commit, blob, commitHash
        )
        if entropicDiff:
            issues = issues.union(entropicDiff)

        found_regexes = regex_check(
            printableDiff, commit_time, branch_name, prev_commit, blob, commitHash
        )
        issues = issues.union(found_regexes)

        issues = issues.union(foundIssues)
    return issues


def find_strings(
    git_url,
    since_commit=None,
    max_depth=1000000,
    printJson=False,
    do_regex=True,
    do_entropy=True,
    surpress_output=True,
    custom_regexes={},
    branch=None,
    repo_path=None,
):
    output = set()
    if repo_path:
        project_path = repo_path
    else:
        project_path = clone_git_repo(git_url)
    repo = Repo(project_path)
    already_searched = set()
    output_dir = tempfile.mkdtemp()

    if branch:
        branches = repo.remotes.origin.fetch(branch)
    else:
        branches = repo.remotes.origin.fetch()

    for remote_branch in branches:
        since_commit_reached = False
        branch_name = remote_branch.name
        prev_commit = None
        for curr_commit in repo.iter_commits(branch_name, max_count=max_depth):
            commitHash = curr_commit.hexsha
            if commitHash == since_commit:
                since_commit_reached = True
            if since_commit and since_commit_reached:
                prev_commit = curr_commit
                continue
            # if not prev_commit, then curr_commit is the newest commit. And we have nothing to diff with.
            # But we will diff the first commit with NULL_TREE here to check the oldest code.
            # In this way, no commit will be missed.
            diff_hash = hashlib.md5(
                (str(prev_commit) + str(curr_commit)).encode("utf-8")
            ).digest()
            if not prev_commit:
                prev_commit = curr_commit
                continue
            elif diff_hash in already_searched:
                prev_commit = curr_commit
                continue
            else:
                diff = prev_commit.diff(curr_commit, create_patch=True)
            # avoid searching the same diffs
            already_searched.add(diff_hash)
            foundIssues = diff_worker(
                diff,
                curr_commit,
                prev_commit,
                branch_name,
                commitHash,
                custom_regexes,
                do_entropy,
                do_regex,
                printJson,
                surpress_output,
            )

            output = output.union(foundIssues)

            prev_commit = curr_commit
        # Handling the first commit
        diff = curr_commit.diff(NULL_TREE, create_patch=True)
        foundIssues = diff_worker(
            diff,
            curr_commit,
            prev_commit,
            branch_name,
            commitHash,
            custom_regexes,
            do_entropy,
            do_regex,
            printJson,
            surpress_output,
        )
        output = output.union(foundIssues)
        
    print(project_path)
    print(git_url)
    print(output_dir)
    # output["project_path"] = project_path
    # output["clone_uri"] = git_url
    # output["issues_path"] = output_dir

    return output


if __name__ == "__main__":
    cProfile.run("main()")
