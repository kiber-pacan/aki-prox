#!/bin/bash

# Удаляем переменные из текущей сессии
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ftp_proxy FTP_PROXY no_proxy NO_PROXY

# Удаляем из systemd user environment (если systemctl доступен)
if command -v systemctl >/dev/null 2>&1; then
    systemctl --user unset-environment http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ftp_proxy FTP_PROXY no_proxy NO_PROXY
fi

echo "Прокси переменные удалены из сессии и systemd user environment"