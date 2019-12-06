Feature: Automated creation of a whitelist file that is added to a repository. Trufflehog adds missing entries and removes stale records.

  Scenario: Trufflehog finds no secrets if there are no secrets
    Given We have a repository with no secrets
    When  trufflehog scans the repo
    Then  Trufflehog should find no secrets

  Scenario: Trufflehog finds secrets if there are secrets
    Given We have a repository with secrets
    When  on run Trufflehog on that repository
    Then  Trufflehog should find all secrets

  Scenario: Trufflehog adds a secret to the whitelist.
    Given Theres a secret in the repo, and it's not in the whitelist
    When  trufflehog scans the repo
    Then  Trufflehog should add a record for the new secret

  Scenario: Trufflehog updates a secret on the whitelist.
    Given Theres a secret in the repo, and it's in the whitelist
    When  trufflehog scans the repo
    Then  Trufflehog should update (if required) the record in the whitelist

  Scenario: Trufflehog finds a stale secret on the whitelist.
    Given An existing secret in the list
    When  the secret does not exist in the codebase
    Then  Trufflehog should remove the record

  Scenario: Trufflehog exit code is 0 on finding no secrets
    Given Trufflehog has found no secrets
    When  Trufflehog exits
    Then  the exit code should be 0

  Scenario: Trufflehog exit code is 0 on finding only acknowledged/whitelisted secrets
    Given Trufflehog has found secrets, but they're all on the whitelist and acknowledged
    When  Trufflehog exits
    Then  the exit code should be 0

  Scenario: Trufflehog exit code is 1 on finding secrets
    Given Trufflehog has found secrets, but they're all on the whitelist and acknowledged
    When  Trufflehog exits
    Then  the exit code should be 1