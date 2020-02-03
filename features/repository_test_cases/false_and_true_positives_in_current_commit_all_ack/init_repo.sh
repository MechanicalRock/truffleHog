#!/bin/bash

rm -rf test_repo
mkdir test_repo && cd test_repo

git init

#Commit 1
cat << EOF > test_file.txt
This is a test file
and there are no secrets
EOF
git add test_file.txt
git commit -m "Initial commit"

#Commit Candidate - We aren't commiting these changes as they are the "commit candidate"
cat << EOF > real_key.txt
This is a test file
AKIATHISIS666REALKEY
This is a true positive
EOF

cat << EOF > fake_key.txt
This is a test file
AKIATHISISNOTREALKEY
This is a false positive
EOF

cat << EOF > whitelist.json
[{"acknowledged": true, "commit": "Secrets only found in history", "commitAuthor": "josh.crane@mechanicalrock.io", "commitHash": "73b344290656cc0ee8f506eb6b528f21b202bdb3", "confidence": "High", "date": "2020-02-03 12:36:21", "path": "test_file.txt", "reason": "Amazon AWS Access Key ID", "secretGuid": "ac636847a6ffbbe3bf72d5a70f639c2f", "stringDetected": "AKIATHISIS666REALKEY"}, {"acknowledged": true, "commit": "Real key", "commitAuthor": "josh.crane@mechanicalrock.io", "commitHash": "c9a657848360992b5d32ab0cd6f8702642b81636", "confidence": "High", "date": "2020-02-03 12:36:20", "path": "test_file.txt", "reason": "Amazon AWS Access Key ID", "secretGuid": "97a2e10e6a1aa9fcd9b77e91cc8449ed", "stringDetected": "AKIATHISISNOTREALKEY"}, {"acknowledged": true, "commit": "Real key", "commitAuthor": "josh.crane@mechanicalrock.io", "commitHash": "c9a657848360992b5d32ab0cd6f8702642b81636", "confidence": "High", "date": "2020-02-03 12:36:20", "path": "test_file.txt", "reason": "Amazon AWS Access Key ID", "secretGuid": "f39b7237dfc8bce76911c330c0be5653", "stringDetected": "AKIATHISIS666REALKEY"}}]
EOF

git add fake_key.txt real_key.txt

cd ..