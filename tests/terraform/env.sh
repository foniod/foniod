set -e

cleanup() {
    terraform destroy -input=false -auto-approve
}
trap cleanup quit exit

export OS_AMI=$1

export TF_VAR_ec2_ssh_key_name="$AWS_EC2_SSH_KEY_ID"
export TF_VAR_ec2_ssh_private_key="$(echo $AWS_EC2_SSH_KEY |tr '|' '\n')"
export TF_VAR_ec2_os_ami="$OS_AMI"

id=$(dd if=/dev/urandom bs=256 count=1  2>/dev/null|sha1sum |cut -d\  -f1)
sed "s/RANDOM/$id/" <env.tf.in >env.tf 
