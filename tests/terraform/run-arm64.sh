#!/bin/sh

. ./env.sh

terraform init -input=false
terraform apply -target=null_resource.provision_arm64 -input=false -auto-approve |tee env-setup-output

## set up ssh
ip=$(terraform output arm64_ip)

echo $AWS_EC2_SSH_KEY |tr '|' '\n' >ssh_key 
chmod 600 ssh_key
alias ssh_run="ssh -i ssh_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -nT ubuntu@${ip}"

ssh_run sudo sh provision.sh

terraform destroy -input=false -auto-approve
