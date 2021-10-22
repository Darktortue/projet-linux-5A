#!/bin/bash

#set -xe

### VARIABLES #######################################################################################################################
VARWWW="/var/www"
BOOKSTACK_DIR="${VARWWW}/bookstack"
DBROOTPWD="/root/.db_root.txt"
REMIRPM="http://rpms.remirepo.net/enterprise/remi-release-8.rpm"
CURRENT_IP=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
#DOMAIN="wiki.darktortue.icu" Please see line 89


echo -e "\nDisabling SELinux and configuring firewall settings..."
sleep 1
sed -i s/^SELINUX=.*$/SELINUX=disabled/ /etc/selinux/config && setenforce 0
firewall-cmd --add-service=http --permanent && firewall-cmd --add-service=https --permanent && firewall-cmd --reload
echo
echo "SELinux disabled but you might have to reboot the machine in you face issues."
echo

sleep 1

### Add REMI repo ###################################################################################################################
echo "Installing repo in order to install necessaries packages and dependencies..."
sleep 1
if ! dnf install -y dnf-utils $REMIRPM;
then
        echo -e "\t ERROR on Remi RPM, please check RPM URL : $REMIRPM "
        echo -e "\t script aborted, please restart after fix it "
        exit 1
fi

dnf module -y reset php
dnf module -y enable php:remi-7.3


### PACKAGES INSTALLATION ###########################################################################################################
dnf update -y
dnf install epel-release -y
dnf install unzip mariadb-server nginx php php-cli php-fpm php-json php-gd php-mysqlnd php-xml php-openssl php-tokenizer php-mbstring git -y
echo
echo "Done !"

sleep 1
echo

### Database setup ##################################################################################################################
echo "Database installation..."
sleep 1
systemctl enable --now mariadb.service
echo -e "\n n\n n\n n\n y\n y\n y\n" | mysql_secure_installation

mysql -uroot <<MYSQL_SCRIPT
CREATE DATABASE bookstackdb;
CREATE USER 'bookstackuser'@'localhost' IDENTIFIED BY 'password';
GRANT ALL ON bookstackdb.* TO 'bookstackuser'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

# Set mysql root password
DB_ROOT=$(< /dev/urandom tr -cd 'A-Za-z0-9' | head -c 14)
echo
echo "MariaDB root:${DB_ROOT}" >> $DBROOTPWD && cat $DBROOTPWD
echo
mysql -e "SET PASSWORD FOR root@localhost = PASSWORD('${DB_ROOT}');FLUSH PRIVILEGES;"
echo
echo "Done !"

sleep 1
echo

### PHP-FPM setup ###################################################################################################################
echo "PHP-FPM configuration..."
sleep 1
fpmconf=/etc/php-fpm.d/www.conf
sed -i "s|^listen =.*$|listen = /var/run/php-fpm.sock|" $fpmconf
sed -i "s|^;listen.owner =.*$|listen.owner = nginx|" $fpmconf
sed -i "s|^;listen.group =.*$|listen.group = nginx|" $fpmconf
sed -i "s|^user = apache.*$|user = nginx|" $fpmconf
sed -i "s|^group = apache.*$|group = nginx|" $fpmconf
sed -i "s|^php_value\[session.save_path\].*$|php_value[session.save_path] = ${VARWWW}/sessions|" $fpmconf
echo
echo "Done !"

sleep 1
echo

### SSL CERT ########################################################################################################################
#Unable to perform this operation on ESGI's network that's why it's commented
#echo -e "Remember to setup an A record and to open port 80 or 443 in order for certbot to establish a connection to generate certificates..."
#sleep 4
#echo
#dnf install install certbot python3-certbot-nginx -y
#echo
#certbot certonly --noninteractive --register-unsafely-without-email --agree-tos --standalone -d "$DOMAIN"
#cp -v /etc/letsencrypt/live/"$DOMAIN"/fullchain.pem /etc/nginx/certificats
#cp -v /etc/letsencrypt/live/"$DOMAIN"/privkey.pem /etc/nginx/certificats

### SELF SIGNED SSL CERT ############################################################################################################
echo "Generating SSL certificate..."
sleep 1
mkdir -vp /etc/nginx/certificats
cd /etc/nginx/certificats
openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=FR/ST=Paris/L=Paris/O=ESGI/CN=wiki.esgi.local" \
    -keyout wiki.esgi.local.key \
    -out wiki.esgi.local.crt
cd /etc/nginx
echo "Generation of the dhparam.pem file in /etc/nginx necessary for the proper functioning of the SSL part..."
sleep 2
echo
openssl dhparam -out dhparam.pem 2048
chown -R nginx:nginx /etc/nginx/certificats
echo
echo "Done !"

sleep 1
echo

### NGINX SETUP #####################################################################################################################
echo "Nginx configuration..."
sleep 1
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup

cat << '_EOF_' > /etc/nginx/nginx.conf
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    include /etc/nginx/conf.d/*.conf;
}
_EOF_

cat << '_EOF_' > /etc/nginx/conf.d/bookstack.conf
server {
    listen 80;
    #listen [::]:80;
    access_log  /var/log/nginx/bookstack_access.log;
    error_log   /var/log/nginx/bookstack_error.log;
    server_name wiki.esgi.local;
    root        /var/www/bookstack/public;
    #
    # redirect all HTTP requests to HTTPS with a 301 Moved Permanently response.
    #
    return 301 https://$host$request_uri;
}


server {
  listen 443 ssl http2;
  #listen [..]:443 ssl http2;
  ssl_certificate /etc/nginx/certificats/wiki.esgi.local.crt;
  ssl_certificate_key /etc/nginx/certificats/wiki.esgi.local.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AE;
  ssl_prefer_server_ciphers on;

  ssl_dhparam /etc/nginx/dhparam.pem;

  server_name wiki.esgi.local;

  #HSTS
  add_header Strict-Transport-Security "max-age=63072000" always;

  root /var/www/bookstack/public;

  access_log  /var/log/nginx/bookstack_access.log;
  error_log  /var/log/nginx/bookstack_error.log;

  client_max_body_size 1G;
  fastcgi_buffers 64 4K;

  index  index.php;

  location / {
    try_files $uri $uri/ /index.php?$query_string;
  }

  location ~ ^/(?:\.htaccess|data|config|db_structure\.xml|README) {
    deny all;
  }

  location ~ \.php(?:$|/) {
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_param PATH_INFO $fastcgi_path_info;
    fastcgi_pass unix:/var/run/php-fpm.sock;
  }

  location ~* \.(?:jpg|jpeg|gif|bmp|ico|png|css|js|swf)$ {
    expires 30d;
    access_log off;
  }
}
_EOF_

nginx -t
systemctl restart nginx.service
systemctl --no-pager status nginx.service
systemctl enable --now nginx.service
systemctl enable --now php-fpm.service
echo
echo "Done !"

sleep 1
echo

### BOOKSTACK INSTALLATION ##########################################################################################################
echo "BookStack installation..."
sleep 1
mkdir -vp ${BOOKSTACK_DIR}
mkdir -vp ${VARWWW}/sessions # php sessions

# Clone the latest from the release branch
git clone https://github.com/BookStackApp/BookStack.git --branch release --single-branch ${BOOKSTACK_DIR}

echo
echo "Composer installation..."
sleep 1
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php -r "if (hash_file('sha384', 'composer-setup.php') === '756890a4488ce9024fc62c56153228907f1545c228516cbf63f885e036d37e9a59d27d63f46af1d4d07ee0f76181c7d3') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
php -r "unlink('composer-setup.php');"
export COMPOSER_ALLOW_SUPERUSER=1
cd ${BOOKSTACK_DIR} && /usr/local/bin/composer install --no-dev || exit
echo
echo "Done !"

sleep 1
echo

# Configure .env file
cp -v .env.example .env
sed -i.bak "s|APP_URL=.*|APP_URL=https://wiki.esgi.local|g" ${BOOKSTACK_DIR}/.env
sed -i.bak 's|DB_DATABASE=.*|DB_DATABASE=bookstackdb|g' ${BOOKSTACK_DIR}/.env
sed -i.bak 's|DB_USERNAME=.*|DB_USERNAME=bookstackuser|g' ${BOOKSTACK_DIR}/.env
sed -i.bak "s|DB_PASSWORD=.*|DB_PASSWORD=password|g" ${BOOKSTACK_DIR}/.env


# Set in French if locale is FR
lang=$(locale | grep LANG | cut -d= -f2 | cut -d_ -f1)
if [[ $lang = "fr" ]]; then
        sed -i "s|^# Application URL.*$|APP_LANG=fr\n# Application URL|g" ${BOOKSTACK_DIR}/.env
fi

# Generate and update APP_KEY in .env
cd ${BOOKSTACK_DIR} && php artisan key:generate --no-interaction --force || exit

# Generate database tables and other settings
cd ${BOOKSTACK_DIR} && php artisan migrate --no-interaction --force || exit
echo
echo "Done !"

sleep 1
echo

# Fix rights
chown -R nginx:nginx /var/www/{bookstack,sessions}
chmod -R 755 bootstrap/cache public/uploads storage

echo -e "\n\n"
echo -e "\t * 1 * PLEASE NOTE the MariaDB password root:${DB_ROOT}"
echo -e "\t * 2 * REMEMBER TO SETUP YOUR /ETC/HOSTS FILE IN ORDER TO ACCESS THE BOOKSTACK SERVER"
echo -e "\t * 3 * CONNECT to https://wiki.esgi.local with default credentials = admin@admin.com:password"