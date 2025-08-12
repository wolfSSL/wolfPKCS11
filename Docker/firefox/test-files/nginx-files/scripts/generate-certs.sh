#!/bin/bash
#
#

CERT_DIR="../certs"
DAYS_VALID=365
KEY_SIZE=2048
ECC_CURVE="prime256v1"
COUNTRY="US"
STATE="State"
LOCALITY="City"
ORGANIZATION="Organization"
COMMON_NAME="localhost"

mkdir -p $CERT_DIR

echo "Generating RSA certificate..."
openssl req -x509 -nodes -days $DAYS_VALID -newkey rsa:$KEY_SIZE \
  -keyout $CERT_DIR/server-rsa.key -out $CERT_DIR/server-rsa.crt \
  -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/CN=$COMMON_NAME" \
  -addext "subjectAltName = DNS:localhost,IP:127.0.0.1"

echo "Generating ECC certificate..."
openssl ecparam -genkey -name $ECC_CURVE -out $CERT_DIR/server-ecc.key
openssl req -new -key $CERT_DIR/server-ecc.key -x509 -nodes -days $DAYS_VALID \
  -out $CERT_DIR/server-ecc.crt \
  -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/CN=$COMMON_NAME" \
  -addext "subjectAltName = DNS:localhost,IP:127.0.0.1"

echo "Generating DH parameters..."
openssl dhparam -out $CERT_DIR/dhparam.pem 2048

echo "Certificates generated successfully in $CERT_DIR"
echo "  - RSA certificate: $CERT_DIR/server-rsa.crt"
echo "  - RSA key: $CERT_DIR/server-rsa.key"
echo "  - ECC certificate: $CERT_DIR/server-ecc.crt"
echo "  - ECC key: $CERT_DIR/server-ecc.key"
echo "  - DH parameters: $CERT_DIR/dhparam.pem"
