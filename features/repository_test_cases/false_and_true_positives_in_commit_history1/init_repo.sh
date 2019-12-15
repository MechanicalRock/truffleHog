#!/bin/bash

rm -rf test_repo
mkdir test_repo && cd test_repo

git init

#Test Case 1
cat << EOF > test_file.txt
This is a test file
AKIATHISISNOTREALKEY
This is a false positive
EOF
git add test_file.txt
git commit -m "Fake key"

#Test Case 2
cat << EOF > test_file.txt
This is a test file
AKIATHISIS666REALKEY
This is a true positive
EOF
git add test_file.txt
git commit -m "Real key"

#Test Case 3
cat << EOF > test_file.txt
This is a test file
and there are no secrets
EOF
git add test_file.txt
git commit -m "Secrets only found in history"

cd ..