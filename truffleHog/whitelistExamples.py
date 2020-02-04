from truffleHog.whitelist import WhitelistEntry

MockedWhitelistUnacknowledged = [
    WhitelistEntry(
        commit="fixing unicode commit message problem",
        commitAuthor="flower@flowers-MacBook-Pro.local",
        commitHash="7147cc7525c27d459152548e3284e03a73688907",
        confidence="Low",
        date="2016-12-31 23:15:08",
        path="truffleHog.py",
        reason="High Entropy",
        secretGuid="5beef298005122c34d8bab7abd1ef842",
        stringDetected="1234567890abcdefABCDEF",
    )
]

MockedWhitelistAcknowledged = WhitelistEntry(
    classification="FALSE_POSITIVE",
    commit="fixing unicode commit message problem",
    commitAuthor="flower@flowers-MacBook-Pro.local",
    commitHash="7147cc7525c27d459152548e3284e03a73688907",
    confidence="Low",
    date="2016-12-31 23:15:08",
    path="truffleHog.py",
    reason="High Entropy",
    secretGuid="5beef298005122c34d8bab7abd1ef842",
    stringDetected="1234567890abcdefABCDEF",
)
MockedWhitelistAcknowledged = [MockedWhitelistAcknowledged]
