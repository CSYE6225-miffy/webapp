#!/bin/bash

# login authentication
export GITHUB_TOKEN=$(cat "$HOME/miffyyyy_webapp_token")
gh auth login --hostname "github.com"

# set text editor
gh config set editor emacs

# check login status
gh auth status

# test workflow
gh workflow run "CI Push"
echo "https://github.com/miffyyyy/webapp/actions"
