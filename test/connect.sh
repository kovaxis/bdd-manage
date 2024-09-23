#!/bin/bash

USER=admin
PASS=password

echo "Connecting to test container at localhost:10022"
sshpass -p "$PASS" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 10022 $USER@localhost
