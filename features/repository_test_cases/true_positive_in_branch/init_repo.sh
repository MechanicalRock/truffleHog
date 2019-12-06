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

git checkout -b secret_branch

#Commit to secret_branch"
cat << EOF > real_key.txt
This is a test file
AKIATHISIS666REALKEY
This is a true positive
EOF

git add real_key.txt
git commit -m "Secret commit"

#Commit 2 to master
git checkout master

cat << EOF > test_file.txt
This is a test file
and there are no secrets, still...
EOF

git add test_file.txt
git commit -m "Second commit"

cd ..