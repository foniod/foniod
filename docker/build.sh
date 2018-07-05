#!/bin/sh -e

cwd=$(pwd)
if [ "x${cwd##*/}" = "xdocker" ]; then
    cd ..
fi

docker build -f docker/Dockerfile.builder -t ingraind-build docker
docker build $@ -f docker/Dockerfile -t ingraind .
