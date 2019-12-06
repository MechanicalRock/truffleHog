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

#Commit 2
cat << EOF > test_file.txt
This is a test file
and there are no secrets, still
EOF

git add test_file.txt
git commit -m "Second commit"

#Commit 2
cat << EOF > test_file.txt
This is a test file
and there are no secrets, still...
EOF

git add test_file.txt
git commit -m "Third commit"

cd ..