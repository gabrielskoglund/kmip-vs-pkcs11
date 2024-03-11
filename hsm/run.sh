#!/bin/sh

set -e

# Set up a PKCS#11 server connecting to SoftHSM
# Ref: https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html

# Set up a SoftHSM token
softhsm2-util --init-token --slot 0 --label "token" --so-pin "foobar" --pin "foobar"

# Extract the token URL
url=$(p11tool --list-token-urls)

# Start the p11-kit server.
p11-kit server --provider /usr/lib/softhsm/libsofthsm2.so --name /tmp/p11-server "$url"

# Start the ssh server
ssh-keygen -A
mkdir /run/sshd
/usr/sbin/sshd -e -o AllowTcpForwarding=yes -o PermitRootLogin=yes

# Start the KMIP server
python kmip_server.py "$@"
