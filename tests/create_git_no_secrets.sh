#!/bin/sh
mkdir nosecrets && cd nosecrets
git init

#Repo with no secrets
cat << EOF > test_file.txt
This is a test file
and there are no secrets
EOF
git add test_file.txt
git commit -m "Initial commit"
cat << EOF > test_file.txt
This is a test file
and there are still no secrets
EOF
git add test_file.txt
git commit -m "Still no secrets"

cd ..
exit 0