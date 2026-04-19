# Ziro Helm Chart

Deploy Ziro to Kubernetes.

## Quick install

```bash
# With inline API key (NOT for production)
helm install ziro ./deploy/helm/ziro \
  --set llm.model="openai/gpt-5.4" \
  --set llm.apiKey="sk-..."

# With existing secret (recommended)
kubectl create secret generic ziro-llm --from-literal=LLM_API_KEY="sk-..."
helm install ziro ./deploy/helm/ziro \
  --set llm.model="openai/gpt-5.4" \
  --set llm.existingSecret=ziro-llm
```

Then port-forward:

```bash
kubectl port-forward svc/ziro 8420:8420
# Panel at http://localhost:8420
```

## Key values

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | 1 | Number of panel replicas (keep at 1 — state is in-process) |
| `llm.model` | "" | LLM identifier, e.g. `openai/gpt-5.4` |
| `llm.existingSecret` | "" | Existing Secret with `LLM_API_KEY` |
| `llm.apiKey` | "" | Inline API key (creates Secret automatically) |
| `config.scopeEnforce` | true | Runtime RoE enforcement |
| `config.checkpointInterval` | 300 | Seconds between scan checkpoints |
| `dind.enabled` | true | Docker-in-Docker sidecar (needs privileged mode) |
| `persistence.enabled` | true | Persistent volume for /workspace |
| `persistence.size` | 20Gi | PVC size |
| `ingress.enabled` | false | Expose via Ingress |

## Docker-in-Docker caveat

DinD requires `securityContext.privileged: true`. If your cluster doesn't allow privileged pods:

1. Disable DinD: `--set dind.enabled=false`
2. Mount the host Docker socket instead (provide a `volumeMounts` override pointing to `/var/run/docker.sock`)
3. Or point `DOCKER_HOST` at an external Docker host via extra env

## Uninstall

```bash
helm uninstall ziro
```

The PVC is retained by default — delete it explicitly if you want to wipe scan history:

```bash
kubectl delete pvc ziro-workspace
```
