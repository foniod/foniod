#!/bin/sh

. ./env.sh
cp /tmp/workspace/bin/ingraind-$OS_AMI ./ingraind

terraform init -input=false
terraform apply -target=null_resource.provision -input=false -auto-approve |tee test-output

modules_loaded=$(<test-output awk -F': ' '/ingraind::grains::ebpf\] Loaded/ { print $NF }' | sort)
test "$modules_loaded" = "$EXPECTED_RESULT"
