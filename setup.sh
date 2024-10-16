#!/bin/bash

# Este script instala todo lo necesario para preparar el servidor para su uso
# Este script es idempotente: es seguro correrlo varias veces

# Sanitización para evitar errores comunes
set -e
cd "$(dirname "$0")"
if [ $# -ne 1 ] || ! id $1 >/dev/null; then
    printf "\033[0;31mUsage: setup.sh <nombre de usuario admin>\033[0m\n"
    exit 1
fi
if [ $EUID -ne 0 ]; then
    printf "\033[0;31mPlease run as root (run with sudo)\033[0m\n"
    exit 1
fi
USER=$1

# Desactivar swap (?)
# Esto puede ser buena idea para que si el servidor se empieza a quedar sin memoria entonces
# mate procesos en lugar de empezar a usar el disco, que hace que el sistema sea
# insoportablemente lento y cueste mucho conectarse para arreglarlo (o directamente
# sea imposible)
# swapoff -va || printf "\033[0;31mNo se pudo desactivar el swap!\033[0m\n"

# Instalar esenciales
echo "Instalando esenciales..."
apt update -y
apt upgrade -y
apt install -y git python3 python3-pip cron nano

# Instalar Apache (servidor web)
echo "Instalando y configurando Apache..."
apt install -y apache2
read -p "Ingrese hostname del servidor (eg. pavlov.ing.puc.cl): " HOSTNAME
sed "s/{HOSTNAME}/$HOSTNAME/g" apache.conf > /etc/apache2/sites-available/000-default.conf
systemctl enable apache2 || true
systemctl start apache2 || /etc/init.d/apache2 start

# Añadir usuario actual a www-data para poder ver las carpetas home de todos los usuarios
usermod -aG www-data $USER

# Configurar SSL con Let's Encrypt
echo "Configurando certificado SSL..."
apt install -y certbot python3-certbot-apache
rm -f /etc/apache2/sites-enabled/000-default-le-ssl.conf /etc/apache2/sites-available/000-default-le-ssl.conf
certbot --apache || printf "\033[0;31mNo se configuró un certificado SSL\033[0m\n"

# Instalar PostgreSQL
echo "Instalando Postgres..."
apt install -y postgresql postgresql-contrib
systemctl enable postgresql || true
systemctl start postgresql || /etc/init.d/postgresql start
sudo -u postgres psql -U postgres -c "ALTER SYSTEM SET max_connections = 200;"
sudo -u postgres psql -U postgres -c "ALTER SYSTEM SET listen_addresses = '*';" # Escuchar por conexiones externas
PG_HBA=$(sudo -u postgres psql -t -P format=unaligned -c 'SHOW hba_file;')
sudo grep -qE 'host\s+all\s+all\s+all' $PG_HBA || echo 'host all all all scram-sha-256' | sudo tee -a $PG_HBA # Permitir conexiones externas
systemctl restart postgresql || /etc/init.d/postgresql restart

# Instalar PHP
echo "Instalando PHP..."
apt install -y php libapache2-mod-php php-pgsql
systemctl restart apache2 || /etc/init.d/apache2 restart

# Agregar scripts al PATH
echo "export PATH=\$PATH:$PWD/bin" > /etc/profile.d/bdd-manage.sh

# Escanear diariamente
echo "1 0 * * * $USER $PWD/bin/userctl scan" > /etc/cron.d/bdd-manage-scan

printf "\033[0;32mServidor configurado!\033[0m\n"
printf "Recuerda crear los usuarios a partir de una lista de alumnos con el comando \033[0;1muserctl\033[0m (puede requerir relogin)\n"
