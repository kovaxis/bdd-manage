#!/bin/bash

set -e
cd "$(dirname "$0")"
cd ..

USER="admin"
PASS="password"

apt install sshpass

docker compose -f test/compose.yaml up --build --force-recreate -d --wait

sshpass -p "$PASS" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 10022 $USER@localhost mkdir /home/$USER/bdd-setup
sshpass -p "$PASS" scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -P 10022 -r * $USER@localhost:/home/$USER/bdd-setup/
sshpass -p "$PASS" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 10022 $USER@localhost -t sudo /home/$USER/bdd-setup/setup.sh

# docker compose -f test/compose.yaml down
