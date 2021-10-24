#!/bin/bash

#set -xe

### VARIABLES #######################################################################################################################
VARWWW="/var/www"
BOOKSTACK_DIR="${VARWWW}/bookstack"
DBROOTPWD="/root/.db_root.txt"
REMIRPM="http://rpms.remirepo.net/enterprise/remi-release-8.rpm"
KEYCLOAK_DIR="/opt/keycloak-15.0.2"
#DOMAIN="wiki.darktortue.icu" Please see line 89


echo -e "\nDisabling SELinux and configuring firewall settings...\n"
sleep 3
sed -i s/^SELINUX=.*$/SELINUX=disabled/ /etc/selinux/config && setenforce 0
firewall-cmd --add-service=http --permanent && firewall-cmd --add-service=https --permanent && firewall-cmd --add-service=mysql --permanent && firewall-cmd --add-port 7222/tcp --permanent&& firewall-cmd --reload
echo
echo "SELinux is getting disabled only during the installation. The script enables it again at the end."
echo

sleep 1

{
echo "127.0.0.1 sso.esgi.local"
echo "127.0.0.1 wiki.esgi.local"
echo "127.0.0.1 cloud.esgi.local"
echo "127.0.0.1 office.esgi.local"
} >> /etc/hosts

### Add REMI repo ###################################################################################################################
dnf makecache -y
dnf update -y
dnf install vim wget git rsync util-linux-user -y
echo -e "Installing repo in order to install necessaries packages and dependencies...\n"
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
dnf install unzip mariadb-server wget nginx php-common php-cli php-fpm php-json php-gd php-mysqlnd php-xml php-openssl php-tokenizer php-mbstring git -y
echo
echo "Done !"

sleep 1
echo

echo -e "Installing BookStack...\n"
sleep 3

### Database setup ##################################################################################################################
echo -e "Database installation...\n"
sleep 3
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
echo "MariaDB credentials root:${DB_ROOT}" > $DBROOTPWD && cat $DBROOTPWD
echo
mysql -e "SET PASSWORD FOR root@localhost = PASSWORD('${DB_ROOT}');FLUSH PRIVILEGES;"

echo -e "Done !"

sleep 3
echo

### PHP-FPM setup ###################################################################################################################
echo -e "PHP-FPM configuration..."
sleep 3
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
echo -e "Generating SSL certificate...\n"
sleep 3
mkdir -vp /etc/nginx/certificats
cd /etc/nginx/certificats || exit
openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=FR/ST=Paris/L=Paris/O=ESGI/CN=wiki.esgi.local" \
    -keyout wiki.esgi.local.key \
    -out wiki.esgi.local.crt
cd /etc/nginx || exit
echo -e "Generation of the dhparam.pem file in /etc/nginx necessary for the proper functioning of the SSL part. It might be long...\n"
openssl dhparam -out dhparam.pem 2048 > /dev/null
chown -R nginx:nginx /etc/nginx/certificats
echo
echo "Done !"

sleep 1
echo

### NGINX SETUP #####################################################################################################################
echo -e "Nginx configuration...\n"
sleep 3
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
    fastcgi_pass 127.0.0.1:9000;
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
mkdir -vp ${BOOKSTACK_DIR}
mkdir -vp ${VARWWW}/sessions # php sessions

# Clone the latest from the release branch
git clone https://github.com/BookStackApp/BookStack.git --branch release --single-branch ${BOOKSTACK_DIR}
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php -r "if (hash_file('sha384', 'composer-setup.php') === '906a84df04cea2aa72f40b5f787e49f22d4c2f19492ac310e8cba5b96ac8b64115ac402c8cd292b8a03482574915d1a8') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
php -r "unlink('composer-setup.php');"
export COMPOSER_ALLOW_SUPERUSER=1
cd ${BOOKSTACK_DIR} && /usr/local/bin/composer install --no-dev || exit
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


### Keycloak setup ##################################################################################################################

echo -e "Installing Keycloak...\n"
sleep 3

echo -e "Installing Keycloak dependencies...\n"
sleep 3
dnf install wget java-1.8.0-openjdk-devel -y
java -version
useradd -s /sbin/nologin -r keycloak
echo
echo "Done !"

sleep 1
echo

echo -e "Extracting Keycloak archive...\n"
cd /opt && wget https://github.com/keycloak/keycloak/releases/download/15.0.2/keycloak-15.0.2.tar.gz
sleep 3
tar -xzf /opt/keycloak-15.0.2.tar.gz
rm -f /opt/keycloak-15.0.2.tar.gz
echo "Done !"

sleep 1
echo


### Database setup ##################################################################################################################

echo -e "Installing and configuring MariaDB database for Keycloak...\n"
sleep 3

mysql -uroot -p"${DB_ROOT}"<<MYSQL_SCRIPT
CREATE DATABASE keycloak CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON keycloak.* TO 'keycloak'@'%' identified by 'toto';
GRANT ALL PRIVILEGES ON keycloak.* TO 'keycloak'@'localhost' identified by 'toto';
FLUSH privileges;
MYSQL_SCRIPT

wget https://cdn.mysql.com//Downloads/Connector-J/mysql-connector-java-8.0.26.tar.gz
mkdir -vp ${KEYCLOAK_DIR}/modules/system/layers/keycloak/com/mysql/main
tar -xzf mysql-connector-java-8.0.26.tar.gz -C ${KEYCLOAK_DIR}/modules/system/layers/keycloak/com/mysql/main
rm -f /opt/mysql-connector-java-8.0.26.tar.gz

cat << '_EOF_' > /opt/keycloak-15.0.2/modules/system/layers/keycloak/com/mysql/main/module.xml
<?xml version="1.0" ?>
<module xmlns="urn:jboss:module:1.3" name="com.mysql">
 <resources>
  <resource-root path="mysql-connector-java-8.0.26.jar" />
 </resources>
 <dependencies>
  <module name="javax.api"/>
  <module name="javax.transaction.api"/>
 </dependencies>
</module>
_EOF_

cat << '_EOF_' > /opt/keycloak-15.0.2/modules/system/layers/keycloak/com/mysql/main/driver.cli
embed-server --server-config=standalone-ha.xml -c

# Add mysql driver if it doesn't already exist
if (outcome != success) of /subsystem=datasources/jdbc-driver=mysql:read-resource
   /subsystem=datasources/jdbc-driver=mysql:add(driver-name=mysql,\
   driver-module-name=com.mysql,\
   driver-class-name=com.mysql.cj.jdbc.Driver,\
   driver-xa-datasource-class-name=com.mysql.cj.jdbc.MysqlXADataSource)
end-if

quit
_EOF_

${KEYCLOAK_DIR}/bin/jboss-cli.sh --file=${KEYCLOAK_DIR}/modules/system/layers/keycloak/com/mysql/main/driver.cli

cat << '_EOF_' > /opt/keycloak-15.0.2/modules/system/layers/keycloak/com/mysql/main/datasource.cli
embed-server --server-config=standalone-ha.xml -c

# Remove old database connection if it exists
if (outcome == success) of /subsystem=datasources/data-source=KeycloakDS:read-resource
   data-source remove --name=KeycloakDS
end-if

# Add new database connection if it does not exist
if (outcome != success) of /subsystem=datasources/xa-data-source=KeycloakDS:read-resource
   xa-data-source add \
      --name=KeycloakDS \
      --driver-name=mysql \
      --jndi-name=java:jboss/datasources/KeycloakDS \
      --user-name=keycloak \
      --password="keycloak" \
      --valid-connection-checker-class-name=org.jboss.jca.adapters.jdbc.extensions.mysql.MySQLValidConnectionChecker \
      --exception-sorter-class-name=org.jboss.jca.adapters.jdbc.extensions.mysql.MySQLExceptionSorter

   /subsystem=datasources/xa-data-source=KeycloakDS/xa-datasource-properties=ServerName:add(value=keycloak)
   /subsystem=datasources/xa-data-source=KeycloakDS/xa-datasource-properties=DatabaseName:add(value=keycloak)
end-if

quit
_EOF_

${KEYCLOAK_DIR}/bin/jboss-cli.sh --file=${KEYCLOAK_DIR}/modules/system/layers/keycloak/com/mysql/main/datasource.cli
echo
echo "Done !"

sleep 1
echo

### Keycloak systemd service ########################################################################################################

echo -e "Creating keycloak systemd service...\n"
sleep 3
cat <<EOF > /etc/systemd/system/keycloak.service
 
[Unit]
Description=Keycloak
After=network.target
 
[Service]
Type=idle
User=keycloak
Group=keycloak
ExecStart=$KEYCLOAK_DIR/bin/standalone.sh -b 0.0.0.0
TimeoutStartSec=600
TimeoutStopSec=600
 
[Install]
WantedBy=multi-user.target
EOF
echo "Done !"

sleep 1
echo

### Keycloak nginx ##################################################################################################################

echo -e "Creation of the SSL certificate for Keycloak and configuration of nginx...\n"
sleep 3
cd /etc/nginx/certificats || exit
openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=FR/ST=Paris/L=Paris/O=ESGI/CN=sso.esgi.local" \
    -keyout keycloak.key \
    -out keycloak.crt

cat << '_EOF_' > /etc/nginx/conf.d/keycloak.conf
upstream keycloak {
# Use IP Hash for session persistence
	ip_hash;

# List of Keycloak servers
	server 127.0.0.1:8080;
}


server {
	listen 80;
	access_log  /var/log/nginx/keycloak_access.log;
  error_log   /var/log/nginx/keycloak_error.log;
	server_name sso.esgi.local;

# Redirect all HTTP to HTTPS
	location / { 
		return 301 https://\$server_name\$request_uri;
	}
}

server {
	listen 443 ssl http2;
	server_name sso.esgi.local;
	
	access_log  /var/log/nginx/keycloak_access.log;
  error_log  /var/log/nginx/keycloak_error.log;

	ssl_certificate /etc/nginx/certificats/keycloak.crt;
	ssl_certificate_key /etc/nginx/certificats/keycloak.key;
	ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AE;
  ssl_prefer_server_ciphers on;
	ssl_session_cache shared:SSL:1m;
	
	ssl_dhparam /etc/nginx/dhparam.pem;
	
	#HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;
  
	
	location / {
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto $scheme;
		proxy_pass http://keycloak;
	}
}

_EOF_

nginx -t
systemctl restart nginx.service
systemctl --no-pager status nginx.service

${KEYCLOAK_DIR}/bin/jboss-cli.sh 'embed-server,/subsystem=undertow/server=default-server/http-listener=default:write-attribute(name=proxy-address-forwarding,value=true)'
${KEYCLOAK_DIR}/bin/jboss-cli.sh 'embed-server,/socket-binding-group=standard-sockets/socket-binding=proxy-https:add(port=443)'
${KEYCLOAK_DIR}/bin/jboss-cli.sh 'embed-server,/subsystem=undertow/server=default-server/http-listener=default:write-attribute(name=redirect-socket,value=proxy-https)'
chown -R keycloak:keycloak ${KEYCLOAK_DIR}
firewall-cmd --add-port=8080/tcp --permanent
systemctl daemon-reload
systemctl enable keycloak.service
systemctl start keycloak.service
systemctl --no-pager status keycloak.service
echo
echo "Done !"

sleep 1
echo

### Keycloak realm creation #########################################################################################################

echo -e "Keycloak realm and user setup...\n"
sleep 3
${KEYCLOAK_DIR}/bin/add-user-keycloak.sh -u admin -p password -r master
systemctl restart keycloak.service
echo -e "\nWaiting for the keycloak web interface to be up...\n"
sleep 5
systemctl --no-pager status keycloak.service

echo

${KEYCLOAK_DIR}/bin/kcadm.sh config credentials --server http://localhost:8080/auth --realm master --user admin --password password
echo
${KEYCLOAK_DIR}/bin/kcadm.sh create realms -s realm=KOLLAB -s enabled=true
echo
${KEYCLOAK_DIR}/bin/add-user-keycloak.sh -r KOLLAB -u nimda -p password
echo
${KEYCLOAK_DIR}/bin/add-user-keycloak.sh -r KOLLAB -u esgi -p esgi
echo
${KEYCLOAK_DIR}/bin/add-user-keycloak.sh -r KOLLAB -u usera -p usera
echo
${KEYCLOAK_DIR}/bin/add-user-keycloak.sh -r KOLLAB -u userb -p userb
echo
${KEYCLOAK_DIR}/bin/add-user-keycloak.sh -r KOLLAB -u userc -p userc
echo
systemctl restart keycloak.service
systemctl --no-pager status keycloak.service
echo
echo "Done !"

sleep 1
echo

### Bookstack .env modification

echo -e "Bookstack .env file modification...\n"
sleep 3
secret=$(curl -k https://sso.esgi.local/auth/realms/KOLLAB/protocol/saml/descriptor | grep -o -P '(?<=<ds:X509Certificate>).*(?=</ds:X509Certificate>)')

cat <<EOF >> /var/www/bookstack/.env
# Set authentication method to be saml2
AUTH_METHOD=saml2

# Set the display name to be shown on the login button.
# (Login with <name>)
SAML2_NAME=SSO_ESGI

# Name of the attribute which provides the user's email address
SAML2_EMAIL_ATTRIBUTE=email

# Name of the attribute to use as an ID for the SAML user.
SAML2_ATTRIBUTE=ID

# Name of the attribute(s) to use for the user's display name
# Can have mulitple attributes listed, separated with a '|' in which
# case those values will be joined with a space.
# Example: SAML2_DISPLAY_NAME_ATTRIBUTES=firstName|lastName
# Defaults to the ID value if not found.
SAML2_DISPLAY_NAME_ATTRIBUTES=Username

# Auto-load metatadata from the IDP
# Setting this to true negates the need to specify the next three options
SAML2_AUTOLOAD_METADATA=false

# Identity Provider entityID URL
SAML2_IDP_ENTITYID=https://sso.esgi.local/auth/realms/KOLLAB

SAML2_IDP_SSO=https://sso.esgi.local/auth/realms/KOLLAB/protocol/saml

SAML2_IDP_x509=$secret

SAML2_IDP_AUTHNCONTEXT=true

SAML2_USER_TO_GROUPS=true

SAML2_GROUP_ATTRIBUTE=role

SAML2_REMOVE_FROM_GROUPS=false

#APP_DEBUG=true
EOF
echo
echo -e "Done !\n"

sleep 1


### Nextcloud #######################################################################################################################

echo -e "\nInstalling Nextcloud...\n"
sleep 3

echo -e "\nInstalling dependencies...\n"
sleep 3
dnf install -y bzip2 php php-gd php-cli php-mbstring php-intl php-curl php-xml php-pecl-apcu \
php-mysqlnd php-gmp php-opcache php-json php-zip php-imagick php-process php-bcmath
echo
echo -e "Done !\n"

sleep 1

echo -e "Configuring database...\n"
sleep 3
mysql -uroot -p"${DB_ROOT}" <<MYSQL_SCRIPT
CREATE USER 'nextclouduser'@'localhost' IDENTIFIED BY 'toto';
CREATE DATABASE IF NOT EXISTS nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
GRANT ALL PRIVILEGES ON nextcloud.* TO nextclouduser@localhost;
FLUSH PRIVILEGES;
EXIT
MYSQL_SCRIPT
echo -e "Done !\n"

sleep 1

echo -e "Downloading and extracting Nextcloud version 22...\n"
sleep 3
wget https://download.nextcloud.com/server/releases/nextcloud-22.2.0.tar.bz2
wget https://download.nextcloud.com/server/releases/nextcloud-22.2.0.tar.bz2.sha256
sha256sum -c nextcloud-22.2.0.tar.bz2.sha256 < nextcloud-22.2.0.tar.bz2
tar -xf nextcloud-22.2.0.tar.bz2 -C /var/www/
rm -v nextcloud-22.2.0.tar.bz2*
mkdir -vp /var/www/nextcloud/data
chown -R nginx:nginx /var/www/nextcloud
echo
echo -e "Done !\n"

sleep 1

echo -e "Creation of the SSL certificate for Nextcloud and configuration of nginx & php-fpm...\n"
sleep 3
cd /etc/nginx/certificats || exit
openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=FR/ST=Paris/L=Paris/O=ESGI/CN=cloud.esgi.local" \
    -keyout cloud.esgi.local.key \
    -out cloud.esgi.local.crt

cat << '_EOF_' > /etc/nginx/conf.d/nextcloud.conf
upstream php-handler {
    server 127.0.0.1:9000;
}

server {
    listen 80;
    listen [::]:80;
    server_name cloud.esgi.local;

    access_log  /var/log/nginx/nextcloud_access.log;
    error_log  /var/log/nginx/nextcloud_error.log;

    # Enforce HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443      ssl http2;
    listen [::]:443 ssl http2;
    server_name cloud.esgi.local;

    access_log  /var/log/nginx/nextcloud_access.log;
    error_log  /var/log/nginx/nextcloud_error.log;

    # Use Mozilla's guidelines for SSL/TLS settings
    # https://mozilla.github.io/server-side-tls/ssl-config-generator/
    ssl_certificate     /etc/nginx/certificats/cloud.esgi.local.crt;
    ssl_certificate_key /etc/nginx/certificats/cloud.esgi.local.key;

    # HSTS settings
    # WARNING: Only add the preload option once you read about
    # the consequences in https://hstspreload.org/. This option
    # will add the domain to a hardcoded list that is shipped
    # in all major browsers and getting removed from this list
    # could take several months.
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;" always;

    # set max upload size and increase upload timeout:
    client_max_body_size 512M;
    client_body_timeout 300s;
    fastcgi_buffers 64 4K;

    # Enable gzip but do not remove ETag headers
    gzip on;
    gzip_vary on;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
    gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

    # Pagespeed is not supported by Nextcloud, so if your server is built
    # with the `ngx_pagespeed` module, uncomment this line to disable it.
    #pagespeed off;

    # HTTP response headers borrowed from Nextcloud `.htaccess`
    add_header Referrer-Policy                      "no-referrer"   always;
    add_header X-Content-Type-Options               "nosniff"       always;
    add_header X-Download-Options                   "noopen"        always;
    add_header X-Frame-Options                      "SAMEORIGIN"    always;
    add_header X-Permitted-Cross-Domain-Policies    "none"          always;
    add_header X-Robots-Tag                         "none"          always;
    add_header X-XSS-Protection                     "1; mode=block" always;

    # Remove X-Powered-By, which is an information leak
    fastcgi_hide_header X-Powered-By;

    # Path to the root of your installation
    root /var/www/nextcloud;

    # Specify how to handle directories -- specifying `/index.php$request_uri`
    # here as the fallback means that Nginx always exhibits the desired behaviour
    # when a client requests a path that corresponds to a directory that exists
    # on the server. In particular, if that directory contains an index.php file,
    # that file is correctly served; if it doesn't, then the request is passed to
    # the front-end controller. This consistent behaviour means that we don't need
    # to specify custom rules for certain paths (e.g. images and other assets,
    # `/updater`, `/ocm-provider`, `/ocs-provider`), and thus
    # `try_files $uri $uri/ /index.php$request_uri`
    # always provides the desired behaviour.
    index index.php index.html /index.php$request_uri;

    # Rule borrowed from `.htaccess` to handle Microsoft DAV clients
    location = / {
        if ( $http_user_agent ~ ^DavClnt ) {
            return 302 /remote.php/webdav/$is_args$args;
        }
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    # Make a regex exception for `/.well-known` so that clients can still
    # access it despite the existence of the regex rule
    # `location ~ /(\.|autotest|...)` which would otherwise handle requests
    # for `/.well-known`.
    location ^~ /.well-known {
        # The rules in this block are an adaptation of the rules
        # in `.htaccess` that concern `/.well-known`.

        location = /.well-known/carddav { return 301 /remote.php/dav/; }
        location = /.well-known/caldav  { return 301 /remote.php/dav/; }

        location /.well-known/acme-challenge    { try_files $uri $uri/ =404; }
        location /.well-known/pki-validation    { try_files $uri $uri/ =404; }

        # Let Nextcloud's API for `/.well-known` URIs handle all other
        # requests by passing them to the front-end controller.
        return 301 /index.php$request_uri;
    }

    # Rules borrowed from `.htaccess` to hide certain paths from clients
    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)(?:$|/)  { return 404; }
    location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console)                { return 404; }

    # Ensure this block, which passes PHP files to the PHP process, is above the blocks
    # which handle static assets (as seen below). If this block is not declared first,
    # then Nginx will encounter an infinite rewriting loop when it prepends `/index.php`
    # to the URI, resulting in a HTTP 500 error response.
    location ~ \.php(?:$|/) {
        # Required for legacy support
        rewrite ^/(?!index|remote|public|cron|core\/ajax\/update|status|ocs\/v[12]|updater\/.+|oc[ms]-provider\/.+|.+\/richdocumentscode\/proxy) /index.php$request_uri;

        fastcgi_split_path_info ^(.+?\.php)(/.*)$;
        set $path_info $fastcgi_path_info;

        try_files $fastcgi_script_name =404;

        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_param HTTPS on;

        fastcgi_param modHeadersAvailable true;         # Avoid sending the security headers twice
        fastcgi_param front_controller_active true;     # Enable pretty urls
        fastcgi_pass php-handler;

        fastcgi_intercept_errors on;
        fastcgi_request_buffering off;
    }

    location ~ \.(?:css|js|svg|gif|png|jpg|ico)$ {
        try_files $uri /index.php$request_uri;
        expires 6M;         # Cache-Control policy borrowed from `.htaccess`
        access_log off;     # Optional: Don't log access to assets
    }

    location ~ \.woff2?$ {
        try_files $uri /index.php$request_uri;
        expires 7d;         # Cache-Control policy borrowed from `.htaccess`
        access_log off;     # Optional: Don't log access to assets
    }

    # Rule borrowed from `.htaccess`
    location /remote {
        return 301 /remote.php$request_uri;
    }

    location / {
        try_files $uri $uri/ /index.php$request_uri;
    }
}

_EOF_

nginx -t
systemctl restart nginx.service
systemctl --no-pager status nginx.service

sed -i.bak "s|listen = .*|listen = 9000|g" /etc/php-fpm.d/www.conf
sed -i.bak "s|listen.acl_users = apache,nginx|;listen.acl_users = apache,nginx|g" /etc/php-fpm.d/www.conf
sed -i.bak "s|;env\[PATH\] = .*|env[PATH] = /usr/local/bin:/usr/bin:/bin|g" /etc/php-fpm.d/www.conf

sed -i.bak "s|opcache.max_accelerated_files=4000|opcache.max_accelerated_files=10000|g" /etc/php.d/10-opcache.ini
sed -i.bak "s|\;opcache.revalidate_freq=2|opcache.revalidate_freq=1|g" /etc/php.d/10-opcache.ini
sed -i.bak "s|\;opcache.save_comments=1|opcache.save_comments=1|g" /etc/php.d/10-opcache.ini

sed -i.bak "s|memory_limit = 128M|memory_limit = 512M|g" /etc/php.ini

systemctl restart php-fpm.service
systemctl --no-pager status php-fpm.service
echo
echo -e "Done !\n"

sleep 1

cd /var/www/nextcloud/ && sudo -u nginx php occ maintenance:install --database "mysql" --database-name "nextcloud"  --database-user "nextclouduser" --database-pass "toto" --admin-user "admin" --admin-pass "admin"

# To add trusted domains
sed -i.bak "/    0 => 'localhost',/a\    1 => 'cloud.esgi.local'," /var/www/nextcloud/config/config.php
echo
echo -e "Done !\n"

sleep 1

### Onlyoffice

echo -e "Installing OnlyOffice...\n"
sleep 3

echo -e "\nInstalling dependencies...\n"
sleep 3
dnf install -y postgresql postgresql-server
echo
echo -e "Done !\n"

sleep 1

echo -e "Configuring database...\n"
sleep 3
postgresql-setup --initdb --unit postgresql
chkconfig postgresql on
sed -i 's#host    all             all             127.0.0.1/32            ident#host    all             all             127.0.0.1/32            trust#;s#host    all             all             ::1/128                 ident#host    all             all             ::1/128                 trust#' /var/lib/pgsql/data/pg_hba.conf
systemctl restart postgresql.service
systemctl --no-pager status postgresql.service
cd /tmp/ || exit
sudo -u postgres psql -c "CREATE DATABASE onlyoffice;"
sudo -u postgres psql -c "CREATE USER onlyoffice WITH password 'onlyoffice';"
sudo -u postgres psql -c "GRANT ALL privileges ON DATABASE onlyoffice TO onlyoffice;"
echo -e "\nDone !\n"

sleep 1

echo -e "Configuring RabbitMQ repo to install it...\n"
sleep 3
cat << '_EOF_' > /etc/yum.repos.d/rabbitmq.repo
##
## Zero dependency Erlang
##

[rabbitmq_erlang]
name=rabbitmq_erlang
baseurl=https://packagecloud.io/rabbitmq/erlang/el/8/$basearch
repo_gpgcheck=1
gpgcheck=1
enabled=1
# PackageCloud's repository key and RabbitMQ package signing key
gpgkey=https://packagecloud.io/rabbitmq/erlang/gpgkey
       https://github.com/rabbitmq/signing-keys/releases/download/2.0/rabbitmq-release-signing-key.asc
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300

[rabbitmq_erlang-source]
name=rabbitmq_erlang-source
baseurl=https://packagecloud.io/rabbitmq/erlang/el/8/SRPMS
repo_gpgcheck=1
gpgcheck=0
enabled=1
# PackageCloud's repository key and RabbitMQ package signing key
gpgkey=https://packagecloud.io/rabbitmq/erlang/gpgkey
       https://github.com/rabbitmq/signing-keys/releases/download/2.0/rabbitmq-release-signing-key.asc
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300

##
## RabbitMQ server
##

[rabbitmq_server]
name=rabbitmq_server
baseurl=https://packagecloud.io/rabbitmq/rabbitmq-server/el/8/$basearch
repo_gpgcheck=1
gpgcheck=0
enabled=1
# PackageCloud's repository key and RabbitMQ package signing key
gpgkey=https://packagecloud.io/rabbitmq/rabbitmq-server/gpgkey
       https://github.com/rabbitmq/signing-keys/releases/download/2.0/rabbitmq-release-signing-key.asc
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300

[rabbitmq_server-source]
name=rabbitmq_server-source
baseurl=https://packagecloud.io/rabbitmq/rabbitmq-server/el/8/SRPMS
repo_gpgcheck=1
gpgcheck=0
enabled=1
gpgkey=https://packagecloud.io/rabbitmq/rabbitmq-server/gpgkey
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300
_EOF_

dnf update -y
dnf -q makecache -y --disablerepo='*' --enablerepo='rabbitmq_erlang' --enablerepo='rabbitmq_server'
dnf install socat logrotate -y

dnf install --repo rabbitmq_erlang --repo rabbitmq_server erlang rabbitmq-server -y

systemctl start rabbitmq-server
systemctl enable rabbitmq-server
systemctl --no-pager status rabbitmq-server
echo -e "\nDone !\n"

sleep 1

echo -e "Installing fonts. It might be long...\n"
sleep 3
dnf install cabextract xorg-x11-font-utils -y
rpm -i https://deac-ams.dl.sourceforge.net/project/mscorefonts2/rpms/msttcore-fonts-installer-2.6-1.noarch.rpm
echo -e "\nDone !\n"

sleep 1

echo -e "Installing Onlyoffice. It might be long...\n"
sleep 3
dnf install -y https://download.onlyoffice.com/repo/centos/main/noarch/onlyoffice-repo.noarch.rpm
dnf install -y onlyoffice-documentserver

systemctl start supervisord
systemctl enable supervisord
systemctl --no-pager status supervisord
echo -e "\nDone !\n"

sleep 1

echo -e "Executing documentserver configuration script...\n"
sleep 3
echo -e "localhost\n onlyoffice\n onlyoffice\n onlyoffice\n localhost\n guest\n guest\n" | bash /usr/bin/documentserver-configure.sh
echo -e "\nDone !\n"

sleep 1

echo -e "Creation of the SSL certificate for OnlyOffice and configuration of nginx...\n"
sleep 3
cd /etc/nginx/certificats || exit
openssl req -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=FR/ST=Paris/L=Paris/O=ESGI/CN=office.esgi.local" \
    -keyout office.esgi.local.key \
    -out office.esgi.local.crt

chown -R nginx:nginx /etc/nginx/certificats

cat << '_EOF_' > /etc/nginx/conf.d/ds.conf
include /etc/nginx/includes/http-common.conf;

## Normal HTTP host
server {
  listen 0.0.0.0:80;
  listen [::]:80 ;
  server_name office.esgi.local;
  server_tokens off;

  access_log  /var/log/nginx/onlyoffice_access.log;
  error_log  /var/log/nginx/onlyoffice_error.log;

  ## Redirects all traffic to the HTTPS host
  root /nowhere; ## root doesn't have to be a valid path since we are redirecting
  rewrite ^ https://$host$request_uri? permanent;
}

#HTTP host for internal services
server {
  listen 127.0.0.1:80;
  listen [::1]:80;
  server_name localhost;
  server_tokens off;

  include /etc/nginx/includes/ds-common.conf;
  include /etc/nginx/includes/ds-docservice.conf;
}

## HTTPS host
server {
  listen 0.0.0.0:443 ssl http2;
  listen [::]:443 ssl http2;
  server_tokens off;
  root /usr/share/nginx/html;

  server_name office.esgi.local;

  access_log  /var/log/nginx/onlyoffice_access.log;
  error_log  /var/log/nginx/onlyoffice_error.log;

  ## Strong SSL Security
  ## https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html
  ssl on;
  ssl_certificate /etc/nginx/certificats/office.esgi.local.crt;
  ssl_certificate_key /etc/nginx/certificats/office.esgi.local.key;
  # Uncomment string below and specify the path to the file with the password if you use encrypted certificate key
  # ssl_password_file {{SSL_PASSWORD_PATH}};
  ssl_verify_client off;

  ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";

  ssl_protocols  TLSv1.2 TLSv1.3;
  #ssl_session_cache  builtin:1000  shared:SSL:10m;

  ssl_prefer_server_ciphers   on;

  add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;" always;
  # add_header X-Frame-Options SAMEORIGIN;
  add_header X-Content-Type-Options nosniff;

  ## [Optional] If your certficate has OCSP, enable OCSP stapling to reduce the overhead and latency of running SSL.
  ## Replace with your ssl_trusted_certificate. For more info see:
  ## - https://medium.com/devops-programming/4445f4862461
  ## - https://www.ruby-forum.com/topic/4419319
  ## - https://www.digitalocean.com/community/tutorials/how-to-configure-ocsp-stapling-on-apache-and-nginx
  # ssl_stapling on;
  # ssl_stapling_verify on;
  # ssl_trusted_certificate /etc/nginx/ssl/stapling.trusted.crt;
  # resolver 208.67.222.222 208.67.222.220 valid=300s; # Can change to your DNS resolver if desired
  # resolver_timeout 10s;

  ## [Optional] Generate a stronger DHE parameter:
  ##   cd /etc/ssl/certs
  ##   sudo openssl dhparam -out dhparam.pem 4096
  ##
  ssl_dhparam /etc/nginx/dhparam.pem;

  include /etc/nginx/includes/ds-*.conf;

}

_EOF_

nginx -t
systemctl restart nginx.service
systemctl --no-pager status nginx.service
echo -e "\nDone !\n"

sleep 1

#This step is only required because we are using self-signed certificates. If you are using a real certificate, DO NOT change this line.
sed 's|"rejectUnauthorized": true|"rejectUnauthorized": false|' -i /etc/onlyoffice/documentserver/default.json
systemctl restart supervisord
systemctl --no-pager status supervisord

#supervisorctl start ds:example
#sed 's,autostart=false,autostart=true,' -i /etc/supervisord.d/ds-example.ini

cd /var/www/nextcloud/apps && git clone https://github.com/ONLYOFFICE/onlyoffice-nextcloud.git onlyoffice
cd /var/www/nextcloud/apps/onlyoffice && git submodule update --init --recursive
chown -R nginx:nginx /var/www/nextcloud
cd /var/www/nextcloud/ && sudo -u nginx php occ config:system:set allow_local_remote_servers --value true --type bool
echo -e "\nDone !\n"

sleep 1

echo -e "You can access the Onlyoffice server at the URL : https://office.esgi.local"
echo -e "\nPlease read the documentation to link the OnlyOffice server with the Nextcloud server.\n"
sleep 5

### HARDENING #######################################################################################################################

echo -e "System hardening...\n"
sleep 3

dnf install -y dnf-automatic psacct sysstat rkhunter fail2ban policycoreutils-python-utils

echo "SHA_CRYPT_MIN_ROUNDS 5000" >> /etc/login.defs
echo "SHA_CRYPT_MAX_ROUNDS 100000" >> /etc/login.defs
sed 's|PASS_MIN_DAYS\t0|PASS_MIN_DAYS\t5|' -i /etc/login.defs
sed 's|PASS_MAX_DAYS\t99999|PASS_MAX_DAYS\t180|' -i /etc/login.defs
sed 's|umask 022|umask 027|' -i /etc/profile
sed 's|UMASK\t\t022|UMASK\t\t027|' -i /etc/login.defs
sed 's|apply_updates = no|apply_updates = yes|' -i /etc/dnf/automatic.conf
{
echo "blacklist firewire-core"
echo "blacklist dccp"
echo "blacklist sctp"
echo "blacklist rds"
echo "blacklist tipc"
} >> /etc/modprobe.d/blacklist.conf

sed 's|expose_php = On|expose_php = Off|' -i /etc/php.ini
sed 's|allow_url_fopen = On|allow_url_fopen = Off|' -i /etc/php.ini
cat << '_EOF_' > /etc/issue.net
###############################################################
#                  This is a private server!                  #
#       All connections are monitored and recorded.           #
#  Disconnect IMMEDIATELY if you are not an authorized user!  #
###############################################################
_EOF_
cat << '_EOF_' > /etc/issue
###############################################################
#                  This is a private server!                  #
#       All connections are monitored and recorded.           #
#  Disconnect IMMEDIATELY if you are not an authorized user!  #
###############################################################
_EOF_

systemctl start psacct.service
systemctl enable psacct.service
echo
systemctl start sysstat.service
systemctl enable sysstat.service

chmod 600 /boot/grub2/grub.cfg
chmod 600 /etc/cron.deny
chmod 600 /etc/crontab
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.weekly
chmod 700 /etc/cron.monthly

cat << '_EOF_' > /etc/sysctl.d/80-lynis.conf
kernel.kptr_restrict = 2
kernel.sysrq = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.log_martians = 1
#net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
fs.protected_regular = 2
fs.protected_fifos = 2
kernel.perf_event_paranoid = 3
kernel.dmesg_restrict = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 3
net.ipv4.conf.default.accept_source_route = 0
kernel.modules_disabled = 1
_EOF_
sysctl --system

echo

rkhunter --update
rkhunter --propupd
chmod o-rx /usr/bin/as

# SSH Hardening
sed -i -e 's/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i "s/#Port 22/Port 7222/g" /etc/ssh/sshd_config
echo -e "Protocol 2 \n" >> /etc/ssh/sshd_config
sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
sed -i "s/#MaxAuthTries 6/MaxAuthTries 3/g" /etc/ssh/sshd_config
sed -i "s/#MaxSessions 10/MaxSessions 2/g" /etc/ssh/sshd_config
sed -i "s/#LogLevel INFO/LogLevel VERBOSE/g" /etc/ssh/sshd_config
#sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config
sed -i "s/#ClientAliveCountMax 3/ClientAliveCountMax 2/g" /etc/ssh/sshd_config
sed -i "s/#AllowAgentForwarding yes/AllowAgentForwarding no/g" /etc/ssh/sshd_config
sed -i "s/#AllowTcpForwarding yes/AllowTcpForwarding no/g" /etc/ssh/sshd_config
sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config
sed -i "s/#TCPKeepAlive yes/TCPKeepAlive no/g" /etc/ssh/sshd_config
sed -i "s/#Compression delayed/Compression NO/g" /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/ssh/ssh_config
echo ""
echo -e "\nHardening SSH effectué !\n"
sleep 2

systemctl start fail2ban
systemctl enable fail2ban

touch /etc/fail2ban/filter.d/nginx-noscript.conf
tee -a /etc/fail2ban/filter.d/nginx-noscript.conf >/dev/null 2>&1 << END
[Definition]
failregex = ^{"log":"<HOST> -.*GET.*(\.php|\.asp|\.exe|\.pl|\.cgi|\.scgi)
ignoreregex =
END

echo "
[sshd]
enabled = true
port = 7222
filter = sshd
logpath = /var/log/auth.log
maxretry = 4
[nginx-noscript]
enabled   = true
port      = http,https
filter    = nginx-noscript
logpath   = /var/log/nginx/*
" >> /etc/fail2ban/jail.local

echo -e "\nEnabling SELinux and configuring it...\n"
sleep 3
sed -i s/^SELINUX=.*$/SELINUX=enforcing/ /etc/selinux/config && setenforce 1

semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/data(/.*)?'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/config(/.*)?'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/apps(/.*)?'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/.htaccess'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/.user.ini'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/3rdparty/aws/aws-sdk-php/src/data/logs(/.*)?'
restorecon -Rv '/var/www/nextcloud/'
setsebool -P httpd_unified 1
setsebool -P httpd_execmem 1
chown -R nginx:nginx /var/lib/php
chcon -t httpd_sys_rw_content_t -R /var/lib/php

semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/bookstack/public/uploads(/.*)?'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/bookstack/storage(/.*)?'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/bookstack/bootstrap/cache(/.*)?'
restorecon -R '/var/www/bookstack'

semanage port -a -t ssh_port_t -p tcp 7222
systemctl restart sshd
systemctl --no-pager status sshd
firewall-cmd --remove-service ssh --permanent
firewall-cmd --reload
echo

cd /root && git clone https://github.com/CISOfy/lynis

echo -e "\n\nInstallation done ! Remember to reboot the machine in order for some kernel hardening to apply.\n"
echo -e "To configure the Keycloak SSO, go to https://sso.esgi.local/auth/admin/KOLLAB/console/ and connect with the credentials nimda:password\n"
echo -e "Read the documentation to configure the SSO clients for nextcloud and bookstack.\n"

echo -e "Good bye !"