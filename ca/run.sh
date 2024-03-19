#!/bin/sh

set -e

# Set up a SSH tunnel to the HSM
ssh -Nf -L "$XDG_RUNTIME_DIR"/p11-kit/pkcs11:/tmp/p11-server \
    -i /root/.ssh/ssh_key \
    -o StrictHostKeyChecking=no \
    hsm

# Keep container running so that we can call the
# experiment script via docker exec
tail -f /dev/null
