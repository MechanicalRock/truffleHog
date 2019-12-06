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

git add fake_key.txt real_key.txt

cd ..