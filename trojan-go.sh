#!/bin/bash

set -e

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
NC="\033[0m"
CONFIG_FILE="./trojan-go.conf"

# —— 1. 安装基本工具 —— 
echo -e "${GREEN}==== 安装基本工具 ====${NC}"
sudo apt update && sudo DEBIAN_FRONTEND=noninteractive apt install -y curl unzip vim wget
echo -e "${GREEN}✅ 工具安装完成${NC}"

# —— 2. 加载配置文件并校验参数 —— 
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
    KEY_FILE="${KEY_PATH%/}/${DOMAIN}.key"
    CERT_FILE="${FULLCHAIN_PATH%/}/${DOMAIN}.crt"
else
    echo -e "${RED}配置文件 $CONFIG_FILE 不存在，请创建后重试。${NC}"
    exit 1
fi

if [[ -z "$DOMAIN" || -z "$KEY_PATH" || -z "$FULLCHAIN_PATH" \
      || -z "$TROJAN_PORT" || -z "$TROJAN_PASSWORD" || -z "$WEBSOCKET_PATH" \
      || -z "$HTTP_PORT" || -z "$FALLBACK_PORT" ]]; then
    echo -e "${RED}配置文件中缺少必需参数，请确保 DOMAIN、KEY_PATH、FULLCHAIN_PATH、TROJAN_PORT、HTTP_PORT、FALLBACK_PORT、TROJAN_PASSWORD、WEBSOCKET_PATH 全部设置。${NC}"
    exit 1
fi

mkdir -p "$KEY_PATH" "$FULLCHAIN_PATH"
chmod 700 "$KEY_PATH"
# —— 2.1 检查 Trojan 端口是否被占用 —— 
check_port_occupied() {
    ss -tunlp | grep -q ":$TROJAN_PORT\b"
}

if check_port_occupied; then
    echo -e "${YELLOW}⚠ 端口 $TROJAN_PORT 被占用，尝试关闭 trojan-go 服务...${NC}"
    if systemctl is-active --quiet trojan-go; then
        sudo systemctl stop trojan-go
        sleep 2
    fi

    if check_port_occupied; then
        echo -e "${RED}错误：端口 $TROJAN_PORT 仍被其他进程占用，请修改配置文件中的 TROJAN_PORT 后重试。${NC}"
        exit 1
    else
        echo -e "${GREEN}✔ 端口 $TROJAN_PORT 已释放，可用${NC}"
    fi
else
    echo -e "${GREEN}✔ 端口 $TROJAN_PORT 可用${NC}"
fi

# —— 3. 检测并安装/启用 Nginx —— 
echo -e "${GREEN}==== 检测 Nginx 服务 ====${NC}"
if command -v nginx &>/dev/null; then
    echo -e "${GREEN}✔ Nginx 已安装${NC}"
    systemctl enable nginx
    systemctl is-active --quiet nginx || systemctl start nginx
    echo -e "${GREEN}✔ Nginx 已启用并运行${NC}"
else
    echo -e "${GREEN}→ Nginx 未安装，正在安装...${NC}"
    sudo apt update && sudo DEBIAN_FRONTEND=noninteractive apt install -y nginx
    systemctl enable nginx
    systemctl start nginx
    echo -e "${GREEN}✔ Nginx 安装并启动完成${NC}"
fi

# —— 3.1 停用 Nginx 默认站点 —— 
DEFAULT_SITES=(
    /etc/nginx/sites-available/default
    /etc/nginx/sites-enabled/default
    /usr/share/nginx/html/index.html
)
for site in "${DEFAULT_SITES[@]}"; do
    if [[ -e "$site" ]]; then
        echo -e "${GREEN}→ 停用默认配置: $site${NC}"
        rm -f "$site"
    fi
done
nginx -t && nginx -s reload
echo -e "${GREEN}✔ 默认站点已停用${NC}"

# —— 3.2 修改主配置，隐藏版本号 —— 
NGINX_CONF="/etc/nginx/nginx.conf"
if ! grep -q "server_tokens off;" "$NGINX_CONF"; then
    echo -e "${GREEN}→ 插入 server_tokens off; 到 $NGINX_CONF 的 http {} 中${NC}"
    sudo sed -i '/http\s*{/a \    server_tokens off;' "$NGINX_CONF"
    nginx -t && systemctl reload nginx
else
    echo -e "${GREEN}✔ server_tokens off; 已存在，跳过修改${NC}"
fi

# —— 3.3 确保包含 sites-enabled 配置 —— 
if ! grep -q "include /etc/nginx/sites-enabled/\*;" /etc/nginx/nginx.conf; then
    echo -e "${GREEN}→ 插入 include /etc/nginx/sites-enabled/*; 到 nginx.conf${NC}"
    sudo sed -i '/http\s*{/a \    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
    nginx -t && systemctl reload nginx
    sleep 1
else
    echo -e "${GREEN}✔ nginx.conf 已包含 sites-enabled 目录，无需修改${NC}"
fi

# —— 4. 检测并放通 UFW 端口 —— 
# 定义要检查的端口变量名数组
PORT_VARS=("HTTP_PORT" "TROJAN_PORT" "FALLBACK_PORT")
# 检查并放通端口函数
check_and_allow_port() {
    local port=$1
    if sudo ufw status | grep -qE "^${port}(/tcp)?\s+ALLOW"; then
        echo "✅ 端口 $port 已放通"
    else
        echo "🚧 端口 $port 未放通，正在放通..."
        sudo ufw allow "$port"
    fi
}

# 遍历配置的端口变量名
for var in "${PORT_VARS[@]}"; do
    port="${!var}"  # 解引用变量名
    if [[ -n "$port" ]]; then
        check_and_allow_port "$port"
    else
        echo "⚠️ 变量 $var 未定义或为空"
    fi
done



# —— 5. 检测并可选卸载已有 Trojan-Go —— 

ACME_ENV="$HOME/.acme_env"

if [[ -f /usr/local/bin/trojan-go || -f /etc/systemd/system/trojan-go.service ]]; then
    echo -e "${GREEN}检测到已有 Trojan-Go 安装。${NC}"
    read -rp "是否彻底卸载已有 Trojan-Go 并重新部署？[y/n]：" confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}→ 正在卸载 Trojan-Go 及其相关文件...${NC}"

        systemctl stop trojan-go 2>/dev/null || true
        systemctl disable trojan-go 2>/dev/null || true
        rm -f /etc/systemd/system/trojan-go.service
        systemctl daemon-reload

        rm -f /usr/local/bin/trojan-go
        rm -rf /etc/trojan-go
        rm -rf /var/log/trojan-go


        rm -f "$KEY_FILE" "$CERT_FILE"

        rm -f /etc/nginx/sites-available/$DOMAIN
        rm -f /etc/nginx/sites-enabled/$DOMAIN
        rm -rf /var/www/$DOMAIN

        nginx -t && nginx -s reload || true

        echo -e "${GREEN}✔ Trojan-Go 及其配置/证书已卸载干净${NC}"

        read -rp "是否同时删除 acme.sh 与自动续期任务？[y/n]：" acme_confirm
        if [[ "$acme_confirm" =~ ^[Yy]$ ]]; then
            echo -e "${GREEN}→ 删除 acme.sh 及 cron 任务...${NC}"
            crontab -l 2>/dev/null | grep -v 'acme.sh ' | crontab -
            rm -rf ~/.acme.sh
            rm -rf $ACME_ENV
            echo -e "${GREEN}✔ acme.sh 已删除${NC}"
        fi

    else
        echo -e "${RED}用户取消卸载，退出部署。${NC}"
        exit 1
    fi
fi


# —— 6. 安装 Trojan-Go 函数 —— 
install_trojan_go() {
    echo -e "${GREEN}下载并安装 Trojan-Go...${NC}"
    mkdir -p /opt/trojan-go && cd /opt/trojan-go
    if ! wget -q https://github.com/p4gefau1t/trojan-go/releases/latest/download/trojan-go-linux-amd64.zip;then
    	echo -e "${RED}下载 Trojan-Go 失败！${NC}"
    	exit 1
	fi
    unzip -o trojan-go-linux-amd64.zip > /dev/null
    chmod +x trojan-go
    mv trojan-go /usr/local/bin/trojan-go
    rm -f trojan-go-linux-amd64.zip
    cd - >/dev/null
    echo -e "${GREEN}✔ Trojan-Go 安装完成${NC}"
}

# —— 7. 创建 Trojan-Go 配置 —— 
create_config() {
    echo -e "${GREEN}创建 Trojan-Go 配置文件...${NC}"
    mkdir -p /etc/trojan-go
    cat > /etc/trojan-go/server.json <<EOF
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": $TROJAN_PORT,
  "log_level": 1,
  "log_file": "/var/log/trojan-go/trojan-go.log",
  "remote_addr": "127.0.0.1",
  "remote_port": $HTTP_PORT,
  "password": ["$TROJAN_PASSWORD"],
  "ssl": {
    "cert": "$FULLCHAIN_PATH/${DOMAIN}.crt",
    "key":  "$KEY_PATH/${DOMAIN}.key",
    "fallback_port": $FALLBACK_PORT,
    "sni": "$DOMAIN"
  },
  "websocket": {
    "enabled": true,
    "path": "$WEBSOCKET_PATH",
    "host": "$DOMAIN"
  },
  "tcp": {
    "prefer_ipv6": false
  }
 
}
EOF
    echo -e "${GREEN}✔ Trojan-Go 配置已创建${NC}"
}

# —— 8. 创建 systemd 服务 —— 
create_systemd_service() {
    echo -e "${GREEN}创建 Trojan-Go systemd 服务...${NC}"
    cat > /etc/systemd/system/trojan-go.service <<EOF
[Unit]
Description=Trojan-Go
After=network.target

[Service]
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/server.json
Restart=on-failure
User=root
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo -e "${GREEN}✔ systemd 服务文件已创建${NC}"
}

# —— 9. 启用并启动 Trojan-Go —— 
enable_and_start() {
    echo -e "${GREEN}启用并启动 Trojan-Go 服务...${NC}"
    systemctl daemon-reload
    systemctl enable trojan-go
    mkdir -p /var/log/trojan-go
    if systemctl start trojan-go; then
        sleep 1
        echo -e "${GREEN}✔ Trojan-Go 服务启动成功${NC}"
    else
        echo -e "${RED}✖ Trojan-Go 服务启动失败，查看日志：journalctl -u trojan-go${NC}"
        exit 1
    fi
}

# —— 10. 部署伪装站点 —— 
# —— 10. 部署伪装站点 —— 
deploy_nginx_site() {
    echo -e "${GREEN}部署 Nginx 伪装站点...${NC}"
    SITE_DIR="/var/www/$DOMAIN"
    mkdir -p "$SITE_DIR"
    
    echo -e "${GREEN}→ 下载伪装站点 web.zip...${NC}"
    if wget -qO /tmp/web.zip https://github.com/xyz690/Trojan/raw/master/web.zip; then
        unzip -o /tmp/web.zip -d "$SITE_DIR" >/dev/null
        rm -f /tmp/web.zip
        echo -e "${GREEN}✔ 伪装站点已部署至 $SITE_DIR${NC}"
    else
        echo -e "${RED}✖ 下载伪装站点失败，退出部署。${NC}"
        exit 1
    fi

    cat > /etc/nginx/sites-available/$DOMAIN <<EOF
server {
    listen $HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$server_name:8443$request_uri;
}
server {
    listen $FALLBACK_PORT ssl;
    server_name $DOMAIN;
    root $SITE_DIR;
    index index.html;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_certificate $FULLCHAIN_PATH/${DOMAIN}.crt;
    ssl_certificate_key $KEY_PATH/${DOMAIN}.key;

    location / {
        try_files \$uri \$uri/ =404;
    }


    # 自定义错误页面配置
    error_page 404 /error_pages/404.html;
    error_page 500 502 503 504 /error_pages/500.html;
    location = /error_pages/404.html {
        root /var/www/$DOMAIN;
        internal;
    }
    location = /error_pages/500.html {
        root /var/www/$DOMAIN;
        internal;
    }

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff";
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "no-referrer-when-downgrade";
    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; object-src 'none';";

    server_tokens off;
}
EOF

    ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/$DOMAIN
    sleep 1
    echo -e "${GREEN}检测 Nginx 配置语法...${NC}"
    nginx -t || { echo -e "${RED}✖ Nginx 配置检测失败，退出部署。${NC}"; exit 1; }
    systemctl restart nginx
    sleep 1
    echo -e "${GREEN}✔ 伪装站点部署完成${NC}"
}


# —— 11. 创建错误页面 —— 
create_error_page() {
    echo -e "${GREEN}创建自定义错误页面...${NC}"
    ERROR_PAGE_DIR="/var/www/$DOMAIN/error_pages"
    mkdir -p "$ERROR_PAGE_DIR"
    cat > "$ERROR_PAGE_DIR/404.html" <<EOF
<html>
    <head><title>Page Not Found</title></head>
    <body><h1>404 - Page Not Found</h1></body>
</html>
EOF
    cat > "$ERROR_PAGE_DIR/500.html" <<EOF
<html>
    <head><title>Internal Server Error</title></head>
    <body><h1>500 - Internal Server Error</h1></body>
</html>
EOF
    chown -R www-data:www-data "/var/www/$DOMAIN"
    echo -e "${GREEN}✔ 错误页面已创建${NC}"
}

#检查服务状态
check_services_status() {
    echo -e "\n${GREEN}==== 服务状态检查 ====${NC}"

    # ---- Nginx 状态检查 ----
    if systemctl is-active --quiet nginx; then
        echo -e "${GREEN}✔ Nginx 服务正在运行${NC}"
    else
        echo -e "${RED}✖ Nginx 服务未运行${NC}"
    fi

    # Nginx 应监听 HTTP_PORT 和 FALLBACK_PORT
    for port in "$HTTP_PORT" "$FALLBACK_PORT"; do
        if ss -tunlp | grep -q ":$port\b"; then
            echo -e "${GREEN}✔ Nginx 正在监听端口 $port${NC}"
        else
            echo -e "${RED}✖ Nginx 未监听端口 $port,nginx服务异常，请排查${NC}"
        fi
    done

    # ---- Trojan-Go 状态检查 ----
    if systemctl is-active --quiet trojan-go; then
        echo -e "${GREEN}✔ Trojan-Go 服务正在运行${NC}"
    else
        echo -e "${RED}✖ Trojan-Go 服务未运行,请查看日志文件/var/log/trojan-go/trojan-go.log ${NC}"
    fi

    # Trojan-Go 应监听 TROJAN_PORT
    if ss -tunlp | grep -q ":$TROJAN_PORT\b"; then
        echo -e "${GREEN}✔ Trojan-Go 正在监听端口 $TROJAN_PORT${NC}"
    else
        echo -e "${RED}✖ Trojan-Go 未监听端口 $TROJAN_PORT${NC}"
    fi
}

# —— 12. 安装 acme.sh —— 
if ! command -v acme.sh &>/dev/null; then
    echo -e "${GREEN}安装 acme.sh...${NC}"
    curl https://get.acme.sh | sh
fi
[ -f "$HOME/.acme.sh/acme.sh.env" ] && source "$HOME/.acme.sh/acme.sh.env"

# —— 13. Cloudflare 验证选择 —— 
#保存环境值，定时任务续签

if [[ ! -f "$ACME_ENV" ]]; then
    echo "→ 未检测到 $ACME_ENV，正在创建..."
    cat > "$ACME_ENV" <<EOF

EOF
    chmod 600 "$ACME_ENV"
    echo "✔ 已创建 $ACME_ENV，请根据注释填写你的 Cloudflare 凭证"
else
    echo "✔ 已存在 $ACME_ENV"文件
fi

echo -e "\n请选择 Cloudflare API 验证方式："
echo "1) Global API Key----------老版本trojan-go需要这些信息"
echo "2) API Token-----推荐----------目前版本只提供这个api即可"
read -rp "请输入选项 [1/2]: " TOKEN_OPTION

if [[ "$TOKEN_OPTION" == "1" ]]; then
    read -rp "CF 邮箱: " CF_EMAIL
    read -rp "Global API Key: " CF_Key
    echo "export CF_Email=\"$CF_EMAIL\"" > "$ACME_ENV"
    echo "export CF_Key=\"$CF_Key\"" >> "$ACME_ENV"
    echo -e "${GREEN}使用 Global API Key 模式${NC}"
elif [[ "$TOKEN_OPTION" == "2" ]]; then
    read -rp "API Token: " CF_Token
    echo "export CF_Token=\"$CF_Token\"" > "$ACME_ENV"
    echo -e "${GREEN}使用 API Token 模式${NC}"
else
    echo -e "${RED}无效选项，退出。${NC}"
    exit 1
fi
chmod 600 "$ACME_ENV"

# —— 14. 申请并安装证书 —— 

# 添加自动续签时加载命令
RELOAD_CMD="nginx -s reload && (systemctl is-active --quiet trojan-go && systemctl restart trojan-go || true)"

echo -e "${GREEN}配置 acme.sh 证书源为 Let's Encrypt 并启用 ECC 模式...${NC}"
source "$ACME_ENV"
#使系统能找到acme.sh命令，否则使用绝对路径执行
#export PATH="$HOME/.acme.sh:$PATH"
#默认是ZeroSSL注册方式，必须修改默认使用letsencrypt注册证书
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt 
#默认是rsa证书，切换申请ecc证书.--ecc默认申请的就是-ec256
# 申请证书（带 DNS 验证，自动调用 Cloudflare API）

~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --ecc  || { echo -e "${RED}证书申请失败${NC}"; exit 1; }


#安装证书。acme.sh接管证书，续签无需关注证书位置，手动复制的证书无法被acme.sh续签。
~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
    --key-file "$KEY_FILE" \
    --fullchain-file "$CERT_FILE" \
    --ecc \
    --reloadcmd "$RELOAD_CMD"
chmod 600 "$KEY_FILE"

# —— 15. 添加自动续期任务 —— 

# === 清理旧的 acme.sh cron 任务 ===
echo -e "${GREEN}配置自动续签定时任务...${NC}"
crontab -l 2>/dev/null | grep -v 'acme.sh --cron' | crontab -

# === 添加新的自动续签任务 ===
(crontab -l 2>/dev/null; echo "0 0 * * * /bin/bash -c 'source $ACME_ENV && ~/.acme.sh/acme.sh --cron --home ~/.acme.sh > /dev/null 2>&1'") | crontab -

echo -e "${GREEN}所有配置完成！证书会每日检查并在需要时自动续签。${NC}"


# ===== 关键修复：调整执行顺序 =====
install_trojan_go
create_config
create_systemd_service

# 先创建错误页面（在Nginx配置前）
create_error_page

# 再申请证书（在服务启动前）
# 注意：证书申请代码已在第14步执行

# 然后部署Nginx站点
deploy_nginx_site

# 最后启动Trojan-Go
enable_and_start

echo -e "${GREEN}✅ 全部操作完成，Trojan-Go 与伪装站点部署成功！${NC}"
echo -e "${YELLOW}⚠ 请确保域名 $DOMAIN 已解析到本服务器IP，并开放防火墙端口${NC}"
echo -e "${GREEN}----------开始检查服务状态--------------------${NC}"
check_services_status
