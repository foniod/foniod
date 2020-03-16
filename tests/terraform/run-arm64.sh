#!/bin/sh

. ./env.sh

terraform init -input=false
terraform apply -target=null_resource.provision_arm64 -input=false -auto-approve |tee env-setup-output

## set up ssh
ip=$(terraform output arm64_ip)
ssh_user=$(terraform output ssh_user)

echo $AWS_EC2_SSH_KEY |tr '|' '\n' >ssh_key 
chmod 600 ssh_key
alias ssh_run="ssh -i ssh_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -T ${ssh_user}@${ip}"

tar cz -C ../.. . | ssh_run tar xz -C /home/ubuntu/ingraind
ssh_run -n sudo bash provision.sh || true
ssh_run -n grep -v Measurement /tmp/ingrain.log > test-output
kver=$(ssh_run -n uname -r)

check_result arm64 $kver