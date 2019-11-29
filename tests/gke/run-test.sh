#!/bin/sh

kubectl apply -f config.yaml
kubectl apply -f ingraind.yaml
sleep 10 # this is needed or kubectl logs can fail if a container is starting up but not ready to serve logs
POD=$(kubectl get pods -l app=ingraind -oname | head -n1)
kubectl logs --pod-running-timeout=60s $POD | tee test-output
kubectl delete -f ingraind.yaml
kubectl delete -f config.yaml

modules_loaded=$(<test-output awk -F': ' '/ingraind::grains::ebpf: Loaded/ { print $NF }' | sort)

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
