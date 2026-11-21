#!/usr/bin/env bash
# Same sign/verify/tamper flow as demo1, using only the OpenSSL command line.
# Run from Git Bash / Linux / macOS:  bash openssl_demo.sh
set -u
cd "$(dirname "$0")" && mkdir -p output/openssl && cd output/openssl

echo "== 1. Generate ECDSA P-256 and RSA-2048 key pairs"
openssl ecparam -name prime256v1 -genkey -noout -out ec_priv.pem
openssl ec -in ec_priv.pem -pubout -out ec_pub.pem 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_priv.pem 2>/dev/null
openssl pkey -in rsa_priv.pem -pubout -out rsa_pub.pem

echo "CONTRACT #2026-11: Alice agrees to pay Bob 1,000 USD on 30/11/2026." > contract.txt
echo "CONTRACT #2026-11: Alice agrees to pay Bob 9,000 USD on 30/11/2026." > tampered.txt

echo "== 2. Sign (ECDSA-SHA256 and RSA-PSS-SHA256)"
openssl dgst -sha256 -sign ec_priv.pem -out contract.ecdsa.sig contract.txt
openssl dgst -sha256 -sign rsa_priv.pem -sigopt rsa_padding_mode:pss -out contract.rsa.sig contract.txt

echo "== 3. Verify ORIGINAL (expected: Verified OK)"
openssl dgst -sha256 -verify ec_pub.pem -signature contract.ecdsa.sig contract.txt
openssl dgst -sha256 -verify rsa_pub.pem -sigopt rsa_padding_mode:pss -signature contract.rsa.sig contract.txt

echo "== 4. Verify TAMPERED (expected: Verification failure)"
openssl dgst -sha256 -verify ec_pub.pem -signature contract.ecdsa.sig tampered.txt 2>&1
openssl dgst -sha256 -verify rsa_pub.pem -sigopt rsa_padding_mode:pss -signature contract.rsa.sig tampered.txt 2>&1
