#!/bin/sh

. ./env.sh
cp /tmp/workspace/bin/ingraind-$OS_AMI ./ingraind

terraform init -input=false
terraform apply -target=null_resource.provision -input=false -auto-approve |tee test-output

check_result x64
