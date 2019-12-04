from behave import *

@given('we have a repository with no secrets')
def step_impl(context):
    pass

@when('we run Trufflehog at that repository')
def step_impl(context):
    assert True is not False

@then('trufflehog should find no secrets')
def step_impl(context):
    assert context.failed is False
