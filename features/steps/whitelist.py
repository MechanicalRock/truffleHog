import os, subprocess
from git import Repo
from behave import *
from truffleHog.truffleHog import *
from truffleHog.whitelist import *
from argparse import Namespace


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
    context.repository = test_repos["true_negative_repository"][1]
    context.args = None
    context.command = None


@given("we have a known github repository with secrets")
def step_impl(context):
    context.repository = "https://github.com/MechanicalRock/truffleHog"
    context.args = None
    context.command = None


@when("trufflehog scans the repo in pipeline mode")
def step_impl(context):
    args = Namespace()
    args.repo_path = context.repository
    args.commit = None
    args.pipeline_mode = True
    args.block = True
    context.args = args
    context.command = pipeline_mode


@when("trufflehog scans the repo in console mode")
def step_impl(context):
    args = Namespace()
    args.repo_path = context.repository
    args.commit = None
    args.pipeline_mode = False
    context.args = args
    context.command = console_mode


@then("Trufflehog should find no secrets")
def step_impl(context):
    assert context.command(context.args).whitelist_object == set()


# Trufflehog finds secrets if there are secrets.
@given("we have a repository with secrets")
def step_impl(context):
    context.args = None
    context.command = None
    context.repository = test_repos["false_and_true_positives_in_commit_history"][1]


@then("Trufflehog should find all secrets")
def step_impl(context):
    wls = context.command(context.args)
    assert wls.whitelist_object != set()
    assert ("AKIATHISIS666REALKEY" and "AKIATHISISNOTREALKEY") in str(
        wls.top_secrets()
    )


@then("Trufflehog should add a record for the new secret")
def step_impl(context):
    wls = context.command(context.args)
    assert wls.whitelist_object != set()
    assert len(wls.whitelist_object) == 3


## Behaviour - Whitelist Management
# Trufflehog updates a secret on the whitelist.

# Behaviour - Exit codes
# Trufflehog exit code is 0 on finding no secrets.
@given("Trufflehog has found no secrets")
def step_impl(context):
    context.repository = test_repos["true_negative_repository"][1]


@when("Trufflehog exits")
def step_impl(context):
    WhitelistStatistics(context.scan.possible)


@then("Trufflehog should not include it in the scan result")
def step_impl(context):
    wls = context.command(context.args)
    entry_should_not_exist = {entry for entry in wls.whitelist_object if entry.secretGuid == "c9a657848360992b5d32ab0cd6f8702642b81636"}
    assert entry_should_not_exist == set()


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

# Trufflehog exit code is 0 on finding only acknowledged/whitelisted secrets.


@given(
    "Trufflehog has found secrets, but they're all on the whitelist and acknowledged"
)
def step_impl(context):
    context.repository = test_repos["false_and_true_positives_in_current_commit_all_ack"][1]


@given("Trufflehog has found secrets, they are on the whitelist but not acknowledged")
def step_impl(context):
    context.repository = test_repos["false_and_true_positives_in_commit_history"][1]


@then("the exit code should be 0")
def step_impl(context):
    try:
        wls = context.command(context.args)
        exit_code(wls.whitelist_object, context.args.pipeline_mode)
    except SystemExit as e:
        if e.code == 0:
            pass
        else:
            assert False


@then("the exit code should be 1")
def step_impl(context):
    try:
        wls = context.command(context.args)
        exit_code(wls.whitelist_object, context.args.pipeline_mode)
    except SystemExit as e:
        if e.code == 1:
            pass
        else:
            assert False


@when("trufflehog scans the repo")
def step_impl(context):
    args = Namespace()
    args.repo_path = context.repository
    args.commit = None
    args.pipeline_mode = False
    context.args = args
    context.command = console_mode
    


@given("Theres a secret in the repo, and it's not in the whitelist")
def step_impl(context):
    context.repository = test_repos["false_and_true_positives_in_commit_history"][1]
    context.whitelist = set()
    context.args = None
    context.command = None


@given("Theres a secret in the repo, and it's in the whitelist")
def step_impl(context):
    context.repository = test_repos["false_and_true_positives_in_commit_history"][1]
    context.args = None
    context.command = None

@when("trufflehog scans the repo (commit mode)")
def step_impl(context):
    args = Namespace()
    args.repo_path = context.repository
    args.commit = "739091d4e73973c556461b7bfe3a576e0df086fa"
    args.pipeline_mode = False
    context.args = args
    context.command = console_mode


@then("trufflehog finds all secrets")
def step_impl(context):
    wls = context.command(context.args)
    entries = {entry for entry in wls.whitelist_object if entry.commitHash == "739091d4e73973c556461b7bfe3a576e0df086fa"}
    assert len(entries) == 6