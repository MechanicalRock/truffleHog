Feature: Automated creation of a whitelist file that is added to a repository. Trufflehog adds missing entries and removes stale records.

  Scenario: Trufflehog finds no secrets if there are no secrets
    Given We have a repository with no secrets
    When  trufflehog scans the repo
    Then  Trufflehog should find no secrets

  Scenario: Trufflehog finds secrets if there are secrets
    Given We have a repository with secrets
    When  trufflehog scans the repo
    Then  Trufflehog should find all secrets

  Scenario: Trufflehog adds a secret to the whitelist.
    Given Theres a secret in the repo, and it's not in the whitelist
    When  trufflehog scans the repo
    Then  Trufflehog should add a record for the new secret

  Scenario: Trufflehog updates a secret on the whitelist.
    Given Theres a secret in the repo, and it's in the whitelist
    When  trufflehog scans the repo
    Then  Trufflehog should not include it in the scan result

  Scenario: Trufflehog exit code is 0 on finding no secrets
    Given Trufflehog has found no secrets
    When  trufflehog scans the repo
    Then  the exit code should be 0

  Scenario: Trufflehog exit code is 0 on finding only acknowledged/whitelisted secrets
    Given Trufflehog has found secrets, but they're all on the whitelist and acknowledged
    When  trufflehog scans the repo
    Then  the exit code should be 0

  Scenario: Trufflehog exit code is 1 on finding secrets
    Given Trufflehog has found secrets, they are on the whitelist but not acknowledged
    When  trufflehog scans the repo
    Then  the exit code should be 1

 Scenario: Trufflehog finds secrets in it's own repo (console mode)
    Given we have a known github repository with secrets
    When  trufflehog scans the repo in console mode
    Then  the exit code should be 1

   Scenario: Trufflehog finds secrets in it's own repo (pipeline mode)
    Given we have a known github repository with secrets
    When  trufflehog scans the repo in pipeline mode
    Then  the exit code should be 0

  Scenario: Trufflehog can find a particular commit in it's own repo
    Given we have a known github repository with secrets
    When trufflehog scans the repo (commit mode)
    Then trufflehog finds all secrets