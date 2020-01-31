import os, subprocess
from git import Repo
from behave import *
from truffleHog.truffleHog import *
from truffleHog.whitelist import *


def setup_test_repositories():
    root_dir = os.getcwd()
    for repo_directory in os.listdir("features/repository_test_cases/"):
        subprocess.run(
            "./init_repo.sh",
            check=True,
            cwd=f"features/repository_test_cases/{repo_directory}",
        )

    test_repos = dict()
    os.chdir(root_dir)
    for repo_directory in os.listdir("features/repository_test_cases/"):
        test_repos[repo_directory] = (
            Repo(
                f"features/repository_test_cases/{repo_directory}/test_repo"
            ),  # Repository Object
            f"features/repository_test_cases/{repo_directory}/test_repo/",  # Repository Path
        )
    return test_repos


test_repos = setup_test_repositories()

## Behaviour - Secret finding
# Trufflehog finds no secrets if there are no secrets.
@given("we have a repository with no secrets")
def step_impl(context):
    context.repository = test_repos["true_negative_repository"]


@when("trufflehog scans the repo")
def step_impl(context):
    context.trufflehogScan = find_strings(context.repository[1])


@then("Trufflehog should find no secrets")
def step_impl(context):
    assert context.trufflehogScan == set()


# Trufflehog finds secrets if there are secrets.
@given("we have a repository with secrets")
def step_impl(context):
    context.repository = test_repos["false_and_true_positives_in_commit_history"]


@then("Trufflehog should find all secrets")
def step_impl(context):
    assert context.trufflehogScan != set()
    assert ("AKIATHISIS666REALKEY" and "AKIATHISISNOTREALKEY") in str(
        context.trufflehogScan
    )


@then("Trufflehog should add a record for the new secret")
def step_impl(context):
    for entry in context.trufflehogScan:
        add_to_whitelist(entry, context.whitelist)
    assert context.whitelist != set()


## Behaviour - Whitelist Management
# Trufflehog updates a secret on the whitelist.

# Behaviour - Exit codes
# Trufflehog exit code is 0 on finding no secrets.
@given("Trufflehog has found no secrets")
def step_impl(context):
    context.output = set()
    context.whitelist = set()


@when("Trufflehog exits")
def step_impl(context):
    context.output, context.whitelist = reconcile_secrets(
        context.output, context.whitelist
    )


@then("Trufflehog should not change the whitelist")
def step_impl(context):
    whitelist = set()
    whitelist_comparison = set()

    for entry in context.trufflehogScan:
        add_to_whitelist(entry, whitelist)
    assert whitelist != set()

    for entry in context.trufflehogScan:
        add_to_whitelist(entry, whitelist)
        add_to_whitelist(entry, whitelist_comparison)

    assert whitelist == whitelist_comparison


@given("An existing secret in the list")
def step_impl(context):
    context.whitelist = {
        WhitelistEntry(
            acknowledged=False,
            commit="Fake key",
            commitAuthor="awesomedeveloper@shop.com",
            commitHash="2f19df0dc9d22b2a03f72a9d5f6276e3e3b7d2dd",
            date="2019-12-06 09:16:54",
            path="test_file.txt",
            reason="Amazon AWS Access Key ID",
            secretGuid="b3bf7c97177faa342b60c7171b06300d",
            stringDetected="AKIATHISISNOTREALKEY",
        )
    }


@when("the secret does not exist in the codebase")
def step_impl(context):
    context.output = set()


@then("Trufflehog should remove the record")
def step_impl(context):
    reconcile_secrets(context.output, context.whitelist)
    assert context.whitelist == set()


# Trufflehog exit code is 0 on finding only acknowledged/whitelisted secrets.


@given(
    "Trufflehog has found secrets, but they're all on the whitelist and acknowledged"
)
def step_impl(context):
    context.output = context.whitelist = {
        WhitelistEntry(
            acknowledged=True,
            commit="Fake key",
            commitAuthor="awesomedeveloper@shop.com",
            commitHash="2f19df0dc9d22b2a03f72a9d5f6276e3e3b7d2dd",
            date="2019-12-06 09:16:54",
            path="test_file.txt",
            reason="Amazon AWS Access Key ID",
            secretGuid="b3bf7c97177faa342b60c7171b06300d",
            stringDetected="AKIATHISISNOTREALKEY",
        )
    }
    context.output, context.whitelist = reconcile_secrets(
        context.output, context.whitelist
    )


@given("Trufflehog has found secrets, they are on the whitelist but not acknowledged")
def step_impl(context):
    context.output = context.whitelist = {
        WhitelistEntry(
            acknowledged=False,
            commit="Fake key",
            commitAuthor="awesomedeveloper@shop.com",
            commitHash="2f19df0dc9d22b2a03f72a9d5f6276e3e3b7d2dd",
            date="2019-12-06 09:16:54",
            path="test_file.txt",
            reason="Amazon AWS Access Key ID",
            secretGuid="b3bf7c97177faa342b60c7171b06300d",
            stringDetected="AKIATHISISNOTREALKEY",
        )
    }
    context.output, context.whitelist = reconcile_secrets(
        context.output, context.whitelist
    )


@then("the exit code should be 0")
def step_impl(context):
    try:
        print(context.output)
        assert exit_code(context.output) == sys.exit(0)
    except SystemExit as e:
        if e.code == 0:
            pass
        else:
            assert False


@then("the exit code should be 1")
def step_impl(context):
    try:
        print(context.output)
        assert exit_code(context.output) == sys.exit(1)
    except SystemExit as e:
        if e.code == 1:
            pass
        else:
            assert False


@given("Theres a secret in the repo, and it's not in the whitelist")
def step_impl(context):
    context.repository = test_repos["false_and_true_positives_in_commit_history"]
    context.whitelist = set()


@given("Theres a secret in the repo, and it's in the whitelist")
def step_impl(context):
    context.repository = test_repos["false_and_true_positives_in_commit_history"]
