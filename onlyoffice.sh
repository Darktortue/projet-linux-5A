#!/bin/bash


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

echo -e "Installing fonts...\n"
sleep 3
dnf install cabextract xorg-x11-font-utils -y
rpm -i https://deac-ams.dl.sourceforge.net/project/mscorefonts2/rpms/msttcore-fonts-installer-2.6-1.noarch.rpm
echo -e "\nDone !\n"

sleep 1

echo -e "Installing Onlyoffice...\n"
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