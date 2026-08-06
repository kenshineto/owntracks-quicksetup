#!/usr/bin/env sh

echo "Installing OwnTracks"
ansible-playbook ansible/deploy.yml --inventory=ansible/hosts
