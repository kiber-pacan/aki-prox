#!/bin/bash

http_proxy="http://127.0.0.1:2080"
https_proxy="http://127.0.0.1:2080"
HTTP_PROXY="$http_proxy"
HTTPS_PROXY="$https_proxy"
ftp_proxy="http://127.0.0.1:2080"
FTP_PROXY="$ftp_proxy"
no_proxy="localhost,127.0.0.1,localaddress,.localdomain.com"
NO_PROXY="$no_proxy"

export http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ftp_proxy FTP_PROXY no_proxy NO_PROXY

if command -v systemctl >/dev/null 2>&1; then
    systemctl --user set-environment \
        http_proxy="$http_proxy" \
        https_proxy="$https_proxy" \
        HTTP_PROXY="$HTTP_PROXY" \
        HTTPS_PROXY="$HTTPS_PROXY" \
        ftp_proxy="$ftp_proxy" \
        FTP_PROXY="$FTP_PROXY" \
        no_proxy="$no_proxy" \
        NO_PROXY="$NO_PROXY"
fi

echo "Прокси обновлены в окружении пользователя."