#!/bin/bash

set -e
set -x

on_error() {
	echo '----------------- gecko log -----------------'
    cat /geckodriver.log || true
    echo '----------------- nginx log -----------------'
    cat /var/log/nginx/error.log || true
}

# Setup wolfpkcs11 manifest for firefox
mkdir -p /root/.mozilla/pkcs11-modules
cp wolfPKCS11.json /root/.mozilla/pkcs11-modules/wolfPKCS11.json
# Setup pkcs11.txt file for firefox
mkdir -p /firefox/obj-x86_64-pc-linux-gnu/tmp/profile-default
cp pkcs11.txt /firefox/obj-x86_64-pc-linux-gnu/tmp/profile-default/pkcs11.txt
# Setup nginx responder
pushd nginx-files
cp config/nginx.conf /etc/nginx/nginx.conf
cp -r certs /etc/nginx/certs
cp html/index.html /var/www/html/index.html
nginx
popd
# Setup firefox extension
pushd extension
zip /tmp/extension.xpi *
popd
# Run firefox tests
trap on_error ERR
# Github changes the $HOME dir and Nightly doesn't support that
# https://github.com/microsoft/playwright/issues/6500
export HOME=/root
python3 selenium-test.py
