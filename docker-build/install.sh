#!/bin/sh

chmod +x /rustup-init.sh

groupadd -g 1000 rust
useradd -d /home/rust -m -u 1000 -g 1000 -s /bin/bash rust

mkdir /rustcode
chown -R 1000:1000 /rustcode

su -c '/rustup-init.sh -y --no-modify-path' rust
