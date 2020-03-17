#!/bin/sh

. ./env.sh

terraform init -input=false
terraform apply -target=null_resource.provision -input=false -auto-approve |tee test-output

ip=$(terraform output amd64_ip)
ssh_user=$(terraform output ssh_user)

echo $AWS_EC2_SSH_KEY |tr '|' '\n' >ssh_key
chmod 600 ssh_key
alias ssh_run="ssh -i ssh_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -T ${ssh_user}@${ip}"

kver=$(ssh_run -n uname -r)

check_result x64 $kver
