#!/bin/sh -e

cwd=$(pwd)
if [ "x${cwd##*/}" = "xdocker" ]; then
    cd ..
fi

docker build -f docker/Dockerfile.builder \
       -t quay.io/redsift/ingraind-build:latest \
       -t ingraind-build \
       docker

docker build $@ --build-arg KERNEL_SOURCE=/build/kernel/ \
       -f docker/Dockerfile \
       -t ingraind \
       .
