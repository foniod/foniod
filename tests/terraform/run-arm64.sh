#!/bin/sh

. ./env.sh

terraform init -input=false
terraform apply -target=null_resource.provision_arm64 -input=false -auto-approve |tee env-setup-output

## set up ssh
ip=$(terraform output arm64_ip)

echo $AWS_EC2_SSH_KEY |tr '|' '\n' >ssh_key 
chmod 600 ssh_key
alias ssh_run="ssh -i ssh_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -T ubuntu@${ip}"

tar cz -C ../.. . | ssh_run tar xz -C /home/ubuntu/ingraind
ssh_run -n sudo bash provision.sh || true
ssh_run -n cat /tmp/ingrain.log   >test-output

modules_loaded=$(<test-output awk -F': ' '/ingraind::grains::ebpf: Loaded/ { print $NF }' | sort)
test "$modules_loaded" = "$EXPECTED_RESULT"
