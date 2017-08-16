#!/bin/bash

platforms=( "$@" )

if [ ${#platforms[@]} -eq 0 ]; then
    platforms=( "ubuntu_14.04 ubuntu_16.04 centos7" )
fi

gpg_key=""

if [ -f .gpg-key-id ]; then
    gpg_key="-u $(cat .gpg-key-id)"
fi

for platform in ${platforms[@]}; do
    echo "$platform"
    if docker run --rm -u 1000 -v "$PWD:/rustcode" "snitchbuild:$platform"; then
	gpg2 -a -b $gpg_key -o target/release/audit-snitch.gpg -s target/release/audit-snitch
	mv target "target_$platform"
    else
	echo 'Build failed!'
	exit 1
    fi
done
