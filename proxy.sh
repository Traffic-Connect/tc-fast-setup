#!/bin/bash

# Запрос IP-адреса рабочего сервера
read -p "Введите IP-адрес рабочего сервера (куда проксировать трафик): " WORKER_IP

# Обновление системы и установка nginx
echo "Обновление пакетов и установка nginx..."
apt -y update
apt -y install nginx

# Создание скрипта обновления IP Cloudflare
echo "Создание скрипта cf-ips-update.sh..."
cat > /usr/local/bin/cf-ips-update.sh << 'EOF'
#!/bin/bash

touch /etc/nginx/cloudflare-real-ip.conf

getfile()
{
  wget -q https://www.cloudflare.com/ips-$1 -O /tmp/cf-ips-$1.txt
  if ! [ -s "/tmp/cf-ips-$1.txt" ];
        then
          sleep 5
          getfile;
  fi
  echo >> /tmp/cf-ips-$1.txt
}

getfile v4
getfile v6

echo -e "# Cloudflare\nreal_ip_header    CF-Connecting-IP;" >> /tmp/cf-ips-new.txt

for ip in `cat /tmp/cf-ips-v*.txt`; do
        echo -e "set_real_ip_from $ip;" >> /tmp/cf-ips-new.txt
done
OLD=`md5sum /etc/nginx/cloudflare-real-ip.conf | awk '{print $1}'`
NEW=`md5sum /tmp/cf-ips-new.txt | awk '{print $1}'`
if [ $OLD != $NEW ]; then
        /bin/cp /tmp/cf-ips-new.txt /etc/nginx/cloudflare-real-ip.conf
        systemctl reload nginx
fi
rm -f /tmp/cf-ips-*.txt
EOF

# Делаем скрипт исполняемым
chmod +x /usr/local/bin/cf-ips-update.sh

# Создание cron задачи для автоматического обновления IP Cloudflare
echo "Добавление cron задачи..."
echo '03 05 * * * root /usr/local/bin/cf-ips-update.sh 1>/dev/null 2>/dev/null' > /etc/cron.d/cf-ips

# Создание конфигурации nginx с подставленным IP-адресом
echo "Создание конфигурации nginx..."
cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
worker_rlimit_nofile 166840;

events {
  worker_connections 20000;
  multi_accept on;
  use epoll;
  accept_mutex on;
}

http {

  ##
  # Basic Settings
  ##

  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  types_hash_max_size 2048;
  server_tokens off;

  # server_names_hash_bucket_size 64;
  # server_name_in_redirect off;

  include /etc/nginx/mime.types;
  default_type application/octet-stream;

  ##
  # SSL Settings
  ##
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
  ssl_prefer_server_ciphers on;

  ##
  # Logging Settings
  ##

  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;

  ##
  # Gzip Settings
  ##

  gzip on;
  gzip_disable "msie6";

  gzip_vary on;
  gzip_proxied any;
  gzip_comp_level 3;
  # gzip_buffers 16 8k;
  gzip_http_version 1.1;
  gzip_types text/plain text/css application/json text/xml application/xml application/xml+rss text/javascript application/javascript;

  client_header_timeout 30;
  client_body_timeout 60;
  send_timeout 30;
  connection_pool_size 512;
  client_header_buffer_size 1k;
  large_client_header_buffers 4 4k;
  request_pool_size 8k;
  output_buffers 4 32k;
  postpone_output 1460;
  keepalive_timeout 30s;
  reset_timedout_connection on;
  server_names_hash_bucket_size 128;
  client_max_body_size 30m;
  proxy_connect_timeout 300;
  proxy_send_timeout 300;
  proxy_read_timeout 300;
  proxy_buffer_size 64k;
  proxy_buffers 8 256k;
  proxy_busy_buffers_size 256k;
  proxy_intercept_errors on;
  proxy_temp_path /dev/shm/nginx_proxy_temp 1 2;



  ##
  # Virtual Host Configs
  ##

  include cloudflare-real-ip.conf;

  map \$http_x_forwarded_for \$real_client_ip {
    ~^(\d+\.\d+\.\d+\.\d+) \$1;
    default \$http_cf_connecting_ip;
  }

  server {
    listen 80;
    server_name _;

    include /etc/nginx/cloudflare-real-ip.conf;

    access_log off;
    log_not_found off;
    error_log /dev/null;

    location / {
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_redirect off;
      proxy_set_header X-Real-IP \$real_client_ip;
      proxy_set_header X-Forwarded-For \$real_client_ip;
      proxy_set_header X-Host \$http_host;
      proxy_set_header X-URI \$uri;
      proxy_set_header X-ARGS \$args;
      proxy_set_header Host \$http_host;
      proxy_set_header Refer \$http_refer;
      proxy_pass http://$WORKER_IP;
    }
  }
}
EOF

# Запуск скрипта обновления IP Cloudflare
echo "Запуск скрипта обновления IP Cloudflare..."
/usr/local/bin/cf-ips-update.sh

# Перезагрузка nginx
echo "Перезагрузка nginx..."
systemctl reload nginx

echo "Установка завершена!"
echo "IP рабочего сервера: $WORKER_IP"
echo "Cron задача добавлена для автоматического обновления IP Cloudflare"
