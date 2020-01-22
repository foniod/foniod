#!/bin/sh

. ./env.sh
cp /tmp/workspace/bin/ingraind-$OS_AMI ./ingraind

terraform init -input=false
terraform apply -target=null_resource.provision -input=false -auto-approve |tee test-output

modules_loaded=$(<test-output awk -F': ' '/ingraind::grains::ebpf: Loaded/ { print $NF }' | sort)

cleanup
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
