#!/bin/sh

. ./env.sh

terraform init -input=false
terraform apply -target=null_resource.provision_arm64 -input=false -auto-approve |tee env-setup-output

## set up ssh
ip=$(terraform output arm64_ip)

echo $AWS_EC2_SSH_KEY |tr '|' '\n' >ssh_key 
chown 600 ssh_key
alias ssh="ssh -i ssh_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -nT"

ssh ubuntu@$ip echo 'hey there, ci boi'

terraform destroy -input=false -auto-approve
