#!/bin/sh

# Please set the correct path
MAXQ_SDK=/path/to/maxq10xx-sdk

# Nothing below here needs to be changed.

MAXQ_TOOLBOX=${MAXQ_SDK}/maxq10xx-toolbox/bin

# Zeroize the onboard NV Memory.
${MAXQ_TOOLBOX}/maxq10xx_admin-auth
${MAXQ_TOOLBOX}/maxq10xx_set-state 4
${MAXQ_TOOLBOX}/maxq10xx_set-state 3
sleep 2
${MAXQ_TOOLBOX}/maxq10xx_get-status

# Setup Object ID 1004 to have an ECDSA secp256r1 keypair.
${MAXQ_TOOLBOX}/maxq10xx_admin-auth
${MAXQ_TOOLBOX}/maxq10xx_create-key --key-pair 1004 192 x=rwdgx:x=rwdgx:x=rwdgx
${MAXQ_TOOLBOX}/maxq10xx_key-gen 1004 --ecc SECP256R1 DATASIGNATURE ECDSA-SHA256 NONE NONE

