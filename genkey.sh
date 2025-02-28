#!/bin/bash
function genkey() {
  KEY_FILE="assets/$1-key.pem"
  CERT_FILE="assets/$1-cert.pem"
  CSR_FILE="assets/$1-csr.pem"

  EC_CURVE="secp384r1"

  COUNTRY="BR"
  STATE="São Paulo"
  CITY="São Paulo"
  ORGANIZATION="A organization"
  DNS="www.organization.com.br"

  openssl ecparam -name $EC_CURVE -genkey -out $KEY_FILE

  if [ ! -f $KEY_FILE ]; then
    echo "Error: Failed to generate EC private key."
    exit 1
  fi

  openssl req -new -key $KEY_FILE -out $CSR_FILE -subj \
    "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/CN=$DNS"

  if [ ! -f $CSR_FILE ]; then
    echo "Error: Failed to generate CSR."
    exit 1
  fi

  openssl x509 -req -in $CSR_FILE -signkey $KEY_FILE -out $CERT_FILE -days 365

  if [ ! -f $CERT_FILE ]; then
    echo "Error: Failed to generate self-signed certificate."
    exit 1
  fi

  rm -f $CSR_FILE
}

rm assets/*
genkey "server"
genkey "client"
