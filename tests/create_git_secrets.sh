#!/bin/sh
mkdir secrets && cd secrets
git init

cat << EOF > test_file.txt
This is a test file
and there are no secrets
EOF
git add test_file.txt
git commit -m "Initial commit"

cat << EOF > test_file.txt
This is a test file
and there is a secret!
AKIAIOSFOEN97EXAMPLE
EOF
git add test_file.txt
git commit -m "Oh no! Secret!"
git commit -m "Oh no! Secret!"

cat << EOF > test_file.txt
This is a test file
and I deleted the secret.
It's still in the diff though!
EOF
git add test_file.txt
git commit -m "Secret is gone, but it's still in the diff!!"
git commit -m "Oh no! Secret!" --no-verify # we want to force this secret in

cd ..
exit 0