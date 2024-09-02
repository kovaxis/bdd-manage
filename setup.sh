#!/bin/bash

set -e
cd "$(dirname "$0")"

# Instalar esenciales
echo "Instalando esenciales..."
apt update -y
apt upgrade -y
apt install -y git python3 python3-pip

# Instalar Apache (servidor web)
echo "Instalando y configurando Apache..."
apt install -y apache2
read -p "Ingrese hostname del servidor (eg. pavlov.ing.puc.cl): " HOSTNAME
sed "s/{HOSTNAME}/$HOSTNAME/g" apache.conf > /etc/apache2/sites-available/000-default.conf
systemctl start apache2 || /etc/init.d/apache2 start

# Configurar SSL con Let's Encrypt
echo "Configurando certificado SSL..."
apt install -y certbot python3-certbot-apache
certbot --apache || printf "\033[0;31mNo se configuró un certificado SSL\033[0m\n"

# Instalar PostgreSQL
echo "Instalando Postgres..."
apt install -y postgresql postgresql-contrib
systemctl start postgresql || /etc/init.d/postgresql start
sudo -u postgres psql -U postgres -c "ALTER SYSTEM SET max_connections = 1000;"
systemctl restart postgresql || /etc/init.d/postgresql restart

# Instalar PHP
echo "Instalando PHP..."
apt install -y php libapache2-mod-php php-pgsql
systemctl reload apache2 || /etc/init.d/apache2 reload

# Configurar usuarios
python3 
# TODO: configurar usuarios
# TODO: configurar usuarios de Postgres

printf "\033[0;32mServidor configurado!\033[0m\n"
