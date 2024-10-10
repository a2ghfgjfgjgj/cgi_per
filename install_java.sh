#!/bin/bash

# به‌روزرسانی فهرست بسته‌ها
echo "Updating package list..."
sudo apt update

# نصب JDK
echo "Installing Java Development Kit..."
sudo apt install -y default-jdk

# تایید نصب
echo "Java has been installed."
java -version


echo "deb [signed-by=/etc/apt/keyrings/apache-cassandra.asc] https://debian.cassandra.apache.org 41x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
deb https://debian.cassandra.apache.org 41x main



FOLDER_PATH="/etc/apt/keyrings"

# بررسی وجود فولدر و ایجاد آن اگر وجود نداشته باشد
if [ ! -d "$FOLDER_PATH" ]; then
    echo "Folder $FOLDER_PATH does not exist. Creating now..."
    sudo mkdir -p "$FOLDER_PATH"
    echo "Folder created."
else
    echo "Folder $FOLDER_PATH already exists."
fi


curl -o /etc/apt/keyrings/apache-cassandra.asc https://downloads.apache.org/cassandra/KEYS


sudo apt-get update





sudo apt-get install cassandra



apt install python3-pip

sudo apt-get update


sudo snap install go --classic

sudo apt install php

sudo apt-get update


sudo apt-get install nodejs

sudo apt install npm

pip install python-telegram-bot==13.5

pip install cassandra-driver




pip install python-socketio


pip install requests


go get  

go build main.go 

python3 table.py


sudo apt install ufw



sudo ufw default deny incoming


sudo ufw default allow outgoing



sudo ufw allow ssh



sudo ufw enable
sudo ufw status verbose


sudo ufw allow http



sudo ufw status verbose

npm i

sudo chmod -R 777 /root/cgi_perfect

SERVICE_FILE_GOLANG="/etc/systemd/system/myservice.service"

# ایجاد فایل سرویس با استفاده از هیرداک (here-doc)
sudo tee "$SERVICE_FILE_GOLANG" > /dev/null <<EOF
[Unit]
Description=Run Multiple Programs
After=network.target

[Service]
Type=simple
ExecStart=/root/cgi_perfect/main
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "Systemd service file has been created."
sudo systemctl enable myservice.service


SERVICE_FILE_PHP="/etc/systemd/system/php-server.service"

# ایجاد فایل سرویس با استفاده از هیرداک (here-doc)
sudo tee "$SERVICE_FILE_PHP" > /dev/null <<EOF
[Unit]
Description=PHP Built-in Server
After=network.target

[Service]
User=root
Group=www-data
WorkingDirectory=/root/cgi_perfect/captcha
ExecStart=/usr/bin/php -S localhost:8001
Restart=always

[Install]
WantedBy=multi-user.target

EOF

echo "Systemd service file has been created."

sudo systemctl enable php-server.service
sudo systemctl start php-server.service

sudo systemctl status php-server.service
SERVICE_FILE_BOT="/etc/systemd/system/bot-telegram.service"

# ایجاد فایل سرویس با استفاده از هیرداک (here-doc)
sudo tee "$SERVICE_FILE_BOT" > /dev/null <<EOF

[Unit]
Description=My Python Application
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /root/cgi_perfect/bot_group.py
Restart=always

[Install]
WantedBy=multi-user.target


EOF

echo "Systemd service file has been created."

sudo systemctl enable bot-telegram.service




SERVICE_FILE_SOCKET="/etc/systemd/system/socket-server.service"

# ایجاد فایل سرویس با استفاده از هیرداک (here-doc)
sudo tee "$SERVICE_FILE_SOCKET" > /dev/null <<EOF

[Unit]
Description=Node.js Socket Server

[Service]
ExecStart=/usr/bin/node /root/cgi_perfect/socket.js
Restart=always
User=root
Group=nogroup



[Install]
WantedBy=multi-user.target
EOF

echo "Systemd service file has been created."

sudo systemctl enable socket-server.service
sudo systemctl start socket-server.service

sudo systemctl status socket-server.service

sudo apt update
sudo apt install nginx

sudo ufw allow 'Nginx HTTP'
cat <<EOF > /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    # server_tokens off;

    # server_names_hash_bucket_size 64;
    # server_name_in_redirect off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # SSL Settings
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;

    # Logging Settings
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Gzip Settings
    gzip on;
    # gzip_vary on;
    # gzip_proxied any;
    # gzip_comp_level 6;
    # gzip_buffers 16 8k;
    # gzip_http_version 1.1;
    # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Virtual Host Configs
    server {
        listen 80;
        listen [::]:80;
        server_name _;
        allow 186.2.171.18;  
        deny all;  
        location / {
            proxy_pass http://localhost:8080;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
        }
    }

    server {
        listen 80;
        listen [::]:80;
        server_name socket.perfectmoney.blog;
        location / {
            proxy_pass http://localhost:3000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
        }
    }
}

EOF
sudo systemctl enable nginx

sudo systemctl stop apache2 