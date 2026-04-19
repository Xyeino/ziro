# Ziro Observability Stack

Grafana + Prometheus + Loki + Tempo + promtail as a docker-compose stack.

## Start

```bash
docker compose -f deploy/observability/docker-compose.yml up -d
```

Then point Ziro at the OTLP exporter:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export ZIRO_LLM=openai/gpt-5.4
ziro --panel
```

## Endpoints

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://localhost:3000 | admin / admin (change first login) |
| Prometheus | http://localhost:9090 | - |
| Loki | http://localhost:3100 | - |
| Tempo (API) | http://localhost:3200 | - |
| Tempo OTLP gRPC | localhost:4317 | - |
| Tempo OTLP HTTP | localhost:4318 | - |

## Preloaded dashboard

"Ziro Overview" auto-provisions on Grafana startup under the Ziro folder. It shows:

- Active scans
- Total findings / confirmed ratio
- LLM cost running total
- Token rate
- Tool executions per minute
- Panel logs tail (via Loki)

## Exposing metrics from panel

Ziro already exports to OTel when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Prometheus metrics endpoint is `/api/metrics` on the panel (scraped every 15s by the provisioned `prometheus.yml`).

## Stop + cleanup

```bash
docker compose -f deploy/observability/docker-compose.yml down -v
```
