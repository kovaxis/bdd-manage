#!/bin/bash

USER=admin
PASS=password

cd "$(dirname "$0")"
cd ..

echo "Reuploading bdd-manage files to container at localhost:20022"
sshpass -p "$PASS" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 20022 $USER@localhost rm -r /home/$USER/bdd-manage
sshpass -p "$PASS" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 20022 $USER@localhost mkdir /home/$USER/bdd-manage
sshpass -p "$PASS" scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -P 20022 -r * $USER@localhost:/home/$USER/bdd-manage/
