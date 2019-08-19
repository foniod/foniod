#!/bin/sh

OS_AMI=$1

cp /tmp/workspace/bin/ingraind-$OS_AMI ./ingraind

export TF_VAR_ec2_ssh_key_name="$AWS_EC2_SSH_KEY_ID"
export TF_VAR_ec2_ssh_private_key="$(echo $AWS_EC2_SSH_KEY |tr '|' '\n')"
export TF_VAR_ec2_os_ami="$OS_AMI"

terraform init -input=false
terraform apply -input=false -auto-approve |tee test-output

modules_loaded=$(<test-output awk -F': ' '/ingraind::grains::ebpf: Loaded/ { print $NF }' | sort)

terraform destroy -input=false -auto-approve


exec test "$modules_loaded" = "dns_queries, XDP
tcp_recvmsg, Kprobe
tcp_recvmsg, Kretprobe
tcp_sendmsg, Kprobe
tcp_sendmsg, Kretprobe
tcp_v4_connect, Kprobe
tcp_v4_connect, Kretprobe
udp_rcv, Kprobe
udp_sendmsg, Kprobe
vfs_read, Kprobe
vfs_read, Kretprobe
vfs_write, Kprobe
vfs_write, Kretprobe"
