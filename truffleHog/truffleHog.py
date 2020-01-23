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
from truffleHog.whitelist import (
    WhitelistEntry,
    curate_whitelist,
    whitelist_statistics,
    remediate_secrets,
)
from termcolor import colored

import colorama

colorama.init()  # Color for our windows comrades


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


def _get_repo(repo_path=None, git_url=None):
    try:
        if repo_path:
            project_path = repo_path
        else:
            project_path = _clone_git_repo(git_url)
        return Repo(project_path)
    except Exception as e:
        print(
            colored(
                f"Unable to find a git repository. Are you sure {e} is a valid git repository?",
                "red",
            )
        )
        sys.exit(1)


def _clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path


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


def entropicDiff(
    printableDiff, commit_time, branch_name, prev_commit, path, commitHash
):
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


def regex_check(printableDiff, commit_time, branch_name, prev_commit, path, commitHash):
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


def diff_worker(
    diff, curr_commit, prev_commit, branch_name, commitHash, do_entropy, do_regex
):
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

        foundIssues = set()
        if do_entropy:
            entropic_results = entropicDiff(
                printableDiff, commit_time, branch_name, curr_commit, path, commitHash
            )
            if entropicDiff:
                issues = issues.union(entropic_results)

        if do_regex:
            found_regexes = regex_check(
                printableDiff, commit_time, branch_name, curr_commit, path, commitHash
            )
            issues = issues.union(found_regexes)

        issues = issues.union(foundIssues)
    return issues


def scan_commit(commit, repo):
    curr_commit = repo.commit(commit)
    try:
        prev_commit = curr_commit.parents[0]
    except:
        prev_commit = curr_commit

    branch_name = "NA"
    commitHash = curr_commit.hexsha
    diff = prev_commit.diff(curr_commit, create_patch=True)

    diff = [blob for blob in diff.iter_change_type('M')] + [blob for blob in diff.iter_change_type('A')]
    commit_results = diff_worker(
            diff,
            curr_commit,
            prev_commit,
            branch_name,
            commitHash,
            do_entropy=True,
            do_regex=True,
        )

    return commit_results

def find_strings(
    git_url,
    commit=None,
    repo_path=None,
    do_entropy=True,
    do_regex=True,
):
    repo = _get_repo(repo_path, git_url)
    commits = repo.iter_commits()
    output = set()
    
    if commit:
        commits = [commit]
    
    for commit in commits:
        commit_diff = scan_commit(commit, repo)
        output = output.union(commit_diff)
    return output


def main():
    parser = argparse.ArgumentParser(
        description="Find secrets hidden in the depths of git."
    )

    parser.add_argument("--git_url", type=str, help="A valid repository URL")
    parser.add_argument(
        "--repo_path", type=str, help="File path to git project repository"
    )
    parser.add_argument(
        "--commit", type=str, help="Commit SHA of git commit to scan"
    )
    parser.add_argument(
        "--remediate",
        help="Interactive mode for reconciling secrets",
        action="store_true",
    )
    parser.add_argument(
        "--pipeline_mode",
        help="Flags that secrets should not be output and to run in a pipeline friendly mode.",
        action="store_true",
    )

    args = parser.parse_args()

    if not (args.repo_path or args.git_url):
        # If neither arg is supplied run with the cwd as the path
        args.repo_path = "."

    if args.remediate:
        remediate_secrets()
        sys.exit(0)

    outstanding_secrets = find_strings(args.git_url, repo_path=args.repo_path, commit=args.commit)

    outstanding_secrets = curate_whitelist(outstanding_secrets)

    repo = _get_repo(repo_path=args.repo_path, git_url=args.git_url)
    if not args.pipeline_mode:
        print(f"Working with project path {repo.git_dir}")


    if args.pipeline_mode:
        statistics = whitelist_statistics(args.pipeline_mode)
        if args.commit:
            results = json.dumps(statistics.to_dict_per_commit(repo, args.commit), indent=4)
        else:
            results = json.dumps(statistics.to_dict(), indent=4)
        # Disable terminal color codes in the pipeline if in pipeline mode

        print(results)

        if statistics == False:
            sys.exit(0)
        else:
            sys.exit(1)

    failure_message = None
    for file in repo.untracked_files:
        if file == "whitelist.json":
            failure_message = colored(
                "The whitelist.json file should be commited to source control!",
                "yellow",
            )

    print(colored(whitelist_statistics(args.pipeline_mode), "green"))

    exit_code(outstanding_secrets, failure_message)


def exit_code(output, failure_message=None):
    if output or failure_message:
        if not failure_message:
            print(
                colored(
                    f"Secrets detected: {len(output)}. Please review the output in whitelist.json and either acknowledge the secrets or remediate them",
                    "red",
                )
            )
        else:
            print(failure_message)
        sys.exit(1)
    else:
        print(
            colored(
                "Detected no secrets! Clear to commit whitelist.json and push to remote repository",
                "green",
            )
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
