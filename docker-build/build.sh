#!/bin/bash

make_dockerfile() {
    baseimage=$1
    output=$2

    cat <<EOF > "$output"
FROM $baseimage

COPY update.sh /update.sh
RUN sh /update.sh

COPY packages.sh /packages.sh
RUN sh /packages.sh

COPY install.sh /install.sh
COPY rustup-init.sh /rustup-init.sh
RUN sh /install.sh

RUN rm /install.sh /update.sh /packages.sh

COPY build.sh /build.sh

CMD ["sh", "/build.sh"]
EOF
}

make_dockerfile ubuntu:14.04 ubuntu_14.04/Dockerfile
make_dockerfile ubuntu:16.04 ubuntu_16.04/Dockerfile
make_dockerfile centos:7 centos7/Dockerfile

cp install.sh ubuntu_14.04/install.sh
cp install.sh ubuntu_16.04/install.sh
cp install.sh centos7/install.sh

cp rustup-init.sh ubuntu_14.04/rustup-init.sh
cp rustup-init.sh ubuntu_16.04/rustup-init.sh
cp rustup-init.sh centos7/rustup-init.sh

cp update_ubuntu.sh ubuntu_14.04/update.sh
cp update_ubuntu.sh ubuntu_16.04/update.sh
cp update_centos.sh centos7/update.sh

cp build_nojournald.sh ubuntu_14.04/build.sh
cp build_journald.sh ubuntu_16.04/build.sh
cp build_journald.sh centos7/build.sh

docker build -t snitchbuild:ubuntu_14.04 ubuntu_14.04
docker build -t snitchbuild:ubuntu_16.04 ubuntu_16.04
docker build -t snitchbuild:centos7 centos7
