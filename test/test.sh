#!/bin/bash

set -e
cd "$(dirname "$0")"
cd ..

USER="admin"
PASS="password"

apt install sshpass

docker compose -f test/compose.yaml up --build --force-recreate -d --wait

sshpass -p "$PASS" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 10022 $USER@localhost mkdir /home/$USER/bdd-manage
sshpass -p "$PASS" scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -P 10022 -r * $USER@localhost:/home/$USER/bdd-manage/
sshpass -p "$PASS" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 10022 $USER@localhost -t sudo /home/$USER/bdd-manage/setup.sh

read -p "Detener el contenedor de prueba? (y/N) " -n 1 -r
if [[ $REPLY =~ ^[Nn]$ ]]
then
    printf "Puedes detener el contenedor manualmente con \033[0;1mdocker compose -f test/compose.yaml down\033[0m\n"
else
    docker compose -f test/compose.yaml down
fi
