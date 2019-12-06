import os, subprocess
from git import Repo
from behave import *

test_repos = dict()
for repo_directory in os.listdir("features/repository_test_cases/"):
    test_repos[repo_directory] = (
        Repo(f"features/repository_test_cases/{repo_directory}/test_repo"), # Repository Object
        f"features/repository_test_cases/{repo_directory}/test_repo/"        # Repository Path
    )

## Behaviour - Secret finding
# Trufflehog finds no secrets if there are no secrets.
@given("we have a repository with no secrets")
def step_impl(context):
    context.repository = test_repos["true_negative_repository"]


@when("trufflehog scans the repo")
def step_impl(context):
    context.trufflehogScan = subprocess.run([f"trufflehog {context.repository[1]}"], shell=True, capture_output=True)

@then("Trufflehog should find no secrets")
def step_impl(context):
    assert context.trufflehogScan.results == False
    assert context.trufflehogScan.whitelist == False


# Trufflehog finds secrets if there are secrets.
@given("we have a repository with secrets")
def step_impl(context):
    context.repository = test_repos["false_and_true_positives_in_commity_history"]


@then("Trufflehog should find all secrets")
def step_impl(context):
    assert context.trufflehogScan.results == True

@then("Trufflehog should add a record for the new secret")
def step_impl(context):
    assert True is False


## Behaviour - Whitelist Management
# Trufflehog updates a secret on the whitelist.

# Behaviour - Exit codes
# Trufflehog exit code is 0 on finding no secrets.
@given("Trufflehog has found no secrets")
def step_impl(context):
    assert True is False


@when("Trufflehog exits")
def step_impl(context):
    assert True is False


@then("the exit code should be 0")
def step_impl(context):
    assert context.trufflehogScan.returncode == 0

@then(u'Trufflehog should update (if required) the record in the whitelist')
def step_impl(context):
    raise NotImplementedError(u'STEP: Then Trufflehog should update (if required) the record in the whitelist')


@given(u'An existing secret in the list')
def step_impl(context):
    raise NotImplementedError(u'STEP: Given An existing secret in the list')


@when(u'the secret does not exist in the codebase')
def step_impl(context):
    raise NotImplementedError(u'STEP: When the secret does not exist in the codebase')


@then(u'Trufflehog should remove the record')
def step_impl(context):
    raise NotImplementedError(u'STEP: Then Trufflehog should remove the record')

# Trufflehog exit code is 0 on finding only acknowledged/whitelisted secrets.

@given(u'Trufflehog has found secrets, but they\'re all on the whitelist and acknowledged')
def step_impl(context):
    raise NotImplementedError(u'STEP: Given Trufflehog has found secrets, but they\'re all on the whitelist and acknowledged')

@then("the exit code should be 1")
def step_impl(context):
    assert context.trufflehogScan.returncode == 1

@when(u'on run Trufflehog on that repository')
def step_impl(context):
    raise NotImplementedError(u'STEP: When on run Trufflehog on that repository')


@given(u'Theres a secret in the repo, and it\'s not in the whitelist')
def step_impl(context):
    raise NotImplementedError(u'STEP: Given Theres a secret in the repo, and it\'s not in the whitelist')


@given(u'Theres a secret in the repo, and it\'s in the whitelist')
def step_impl(context):
    raise NotImplementedError(u'STEP: Given Theres a secret in the repo, and it\'s in the whitelist')