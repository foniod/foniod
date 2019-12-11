#!/bin/sh

IMAGE=$1

sed "s#IMAGE#$IMAGE#" <ingraind.yaml.in >ingraind.yaml

kubectl apply -f config.yaml
kubectl apply -f ingraind.yaml

i=0
while [ $(( i+=1 )) -lt 30 ]; do
    POD=$(kubectl get pods -l app=ingraind |grep Running |cut -d\  -f1 | head -n1)
    [ -z "$POD" ] || break;
done

[ -z "$POD" ] && { echo "Failed to start InGRAINd container"; exit 1; }

kubectl logs --pod-running-timeout=60s "$POD" > test-output
kubectl delete -f ingraind.yaml
kubectl delete -f config.yaml

modules_loaded=$(<test-output awk -F': ' '/ingraind::grains::ebpf: Loaded/ { print $NF }' | sort)
echo $modules_loaded

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
