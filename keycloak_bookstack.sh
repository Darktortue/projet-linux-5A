#!/bin/bash

### Keycloak & Bookstack setup ######################################################################################################

dnf install java-1.8.0-openjdk-devel -y
java -version
useradd -s /sbin/nologin -r keycloak
version=15.0.2
mkdir -vp /opt/keycloak/{current,$version}
wget https://github.com/keycloak/keycloak/releases/download/15.0.2/keycloak-15.0.2.tar.gz -P /opt/keycloak/${version}
ln -s /opt/keycloak/$version /opt/keycloak/current
tar -xzvf /opt/keycloak/${version}/keycloak-$version.tar.gz -C /opt/keycloak/current --strip-components=1

### Database setup ##################################################################################################################

mysql -uroot<<MYSQL_SCRIPT
CREATE DATABASE keycloak CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON keycloak.* TO 'keycloak'@'%' identified by 'toto';
GRANT ALL PRIVILEGES ON keycloak.* TO 'keycloak'@'localhost' identified by 'toto';
FLUSH privileges;
MYSQL_SCRIPT

wget https://cdn.mysql.com//Downloads/Connector-J/mysql-connector-java-8.0.26.tar.gz
mkdir -vp /opt/keycloak/current/modules/system/layers/keycloak/com/mysql/main
tar -xzvf mysql-connector-java-8.0.26.tar.gz -C /opt/keycloak/current/modules/system/layers/keycloak/com/mysql/main

cat << '_EOF_' > /opt/keycloak/current/modules/system/layers/keycloak/com/mysql/main/module.xml
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

cat << '_EOF_' > /opt/keycloak/current/modules/system/layers/keycloak/com/mysql/main/driver.cli
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

/opt/keycloak/current/bin/jboss-cli.sh --file=/opt/keycloak/current/modules/system/layers/keycloak/com/mysql/main/driver.cli

cat << '_EOF_' > /opt/keycloak/current/modules/system/layers/keycloak/com/mysql/main/datasource.cli
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

/opt/keycloak/current/bin/jboss-cli.sh --file=/opt/keycloak/current/modules/system/layers/keycloak/com/mysql/main/datasource.cli

### Keycloak systemd service ########################################################################################################

cat << '_EOF_' > /etc/systemd/system/keycloak.service
 
[Unit]
Description=Keycloak
After=network.target
 
[Service]
Type=idle
User=keycloak
Group=keycloak
ExecStart=/opt/keycloak/current/bin/standalone.sh -b 0.0.0.0
TimeoutStartSec=600
TimeoutStopSec=600
 
[Install]
WantedBy=multi-user.target
_EOF_

### Keycloak nginx ##################################################################################################################

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
	ssl_prefer_server_ciphers on;
	
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

opt/keycloak/current/bin/jboss-cli.sh 'embed-server,/subsystem=undertow/server=default-server/http-listener=default:write-attribute(name=proxy-address-forwarding,value=true)'
opt/keycloak/current/bin/jboss-cli.sh 'embed-server,/socket-binding-group=standard-sockets/socket-binding=proxy-https:add(port=443)'
opt/keycloak/current/bin/jboss-cli.sh 'embed-server,/subsystem=undertow/server=default-server/http-listener=default:write-attribute(name=redirect-socket,value=proxy-https)'
chown -R keycloak:keycloak /opt/keycloak
#firewall-cmd --zone=public --add-port=8080/tcp
systemctl daemon-reload
systemctl enable keycloak.service
systemctl start keycloak.service
systemctl --no-pager status keycloak.service

### Keycloak setup ##################################################################################################################

opt/keycloak/current/bin/add-user-keycloak.sh -u admin -p password -r master
systemctl restart keycloak.service
systemctl --no-pager status keycloak.service
opt/keycloak/current/bin/kcadm.sh config credentials --server http://localhost:8080/auth --realm master --user admin --password password
opt/keycloak/current/bin/kcadm.sh create realms -s realm=KOLLAB -s enabled=true
opt/keycloak/current/bin/add-user-keycloak.sh -r KOLLAB -u nimda -p password
systemctl restart keycloak.service
systemctl --no-pager status keycloak.service


### Bookstack .env modification

cat << '_EOF_' >> /var/www/bookstack/.env
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

SAML2_IDP_x509=

SAML2_IDP_AUTHNCONTEXT=true

SAML2_USER_TO_GROUPS=true

SAML2_GROUP_ATTRIBUTE=role

SAML2_REMOVE_FROM_GROUPS=false

#APP_DEBUG=true
_EOF_

echo "Don't forget to add the SAML2_IDP_x509 secret !!"

sleep 2