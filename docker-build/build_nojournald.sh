#!/bin/sh

export PATH="/home/rust/.cargo/bin:$PATH"
cd /rustcode

exec cargo build --release
