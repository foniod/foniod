set -e

cleanup() {
    terraform destroy -input=false -auto-approve
}
trap cleanup quit exit

check_result() {
    arch=$1
    modules_loaded=$(<test-output awk -F': ' '/ingraind::grains::ebpf\] Loaded/ { print $NF }' | sort)
    echo "Modules loaded:"
    echo $modules_loaded

    expected_result="__${arch}_sys_clone, Kprobe
dns_queries, XDP
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

    test "$modules_loaded" = "$expected_result"
}

export OS_AMI=$1

export TF_VAR_ec2_ssh_key_name="$AWS_EC2_SSH_KEY_ID"
export TF_VAR_ec2_ssh_private_key="$(echo $AWS_EC2_SSH_KEY |tr '|' '\n')"
export TF_VAR_ec2_os_ami="$OS_AMI"

id=$(dd if=/dev/urandom bs=256 count=1  2>/dev/null|sha1sum |cut -d\  -f1)
sed "s/RANDOM/$id/" <env.tf.in >env.tf
