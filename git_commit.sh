#!/bin/bash
set -ex

commit_message=$1

git status
git add ./
git commit -m "$commit_message"
git push origin main -f
