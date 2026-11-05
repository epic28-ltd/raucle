# Production Deployment Security Guide

This document covers the security hardening required for production deployment
of the Raucle Gateway.

## TLS Termination

The gateway and admin panel run on plain HTTP. Use a reverse proxy for TLS
termination. The included `docker-compose.gateway.yml` uses Caddy with
automatic Let's Encrypt certificates.

```bash
# Set your domain and admin key
export RAUCLE_DOMAIN=raucle.example.com
export RAUCLE_ADMIN_KEY=$(openssl rand -hex 32)

# Deploy
docker compose -f docker-compose.gateway.yml up -d
```

Caddy provides:
- Automatic TLS via Let's Encrypt
- HTTP-to-HTTPS redirect
- Security headers (HSTS, X-Content-Type-Options, X-Frame-Options)
- Rate limiting (100 requests/minute per IP)
- JSON access logs

## Docker Network Isolation

The gateway container is NOT exposed to the host directly. Only the Caddy
container exposes ports 80 and 443. The gateway runs on an internal Docker
network (`raucle-internal`), making it inaccessible from outside the Docker
host.

```
Internet -> Caddy (80/443) -> raucle-gateway (8080/8081, internal only)
```

## Docker Secrets

Do not bake secrets into the Docker image or pass them as plain environment
variables in production. Use Docker secrets or an external secret manager
(HashiCorp Vault, AWS Secrets Manager).

```bash
# Create a Docker secret for the admin key
echo "your-admin-key" | docker secret create raucle_admin_key -

# Reference in docker-compose:
# environment:
#   - RAUCLE_ADMIN_KEY_FILE=/run/secrets/raucle_admin_key
# secrets:
#   - raucle_admin_key
```

## WAF (Web Application Firewall)

For additional protection of the admin panel, deploy ModSecurity with the
OWASP Core Rule Set in front of Caddy or as a separate container:

```yaml
# Add to docker-compose.gateway.yml:
modsecurity:
  image: owasp/modsecurity-crs:nginx
  ports:
    - "80:80"
  environment:
    - BACKEND=caddy:80
  depends_on:
    - caddy
```

This provides:
- SQL injection detection
- XSS detection
- OWASP Top 10 coverage
- Anomaly scoring

## Health Check Authentication

By default, `/health` is unauthenticated (required for Docker health checks).
To restrict it, set `RAUCLE_HEALTH_KEY`:

```bash
export RAUCLE_HEALTH_KEY=$(openssl rand -hex 16)
```

When set, health checks require the key in the Authorization header:
```bash
curl -H "Authorization: $RAUCLE_HEALTH_KEY" http://localhost:8091/health
```

The Docker healthcheck in the Dockerfile uses `curl -f http://localhost:8081/health`
which will fail if the health key is set. Override the healthcheck in
docker-compose to include the key:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "-H", "Authorization: $$RAUCLE_HEALTH_KEY", "http://localhost:8081/health"]
```

## Audit Log Persistence

Set `RAUCLE_AUDIT_PERSIST=true` to write every gate decision to a JSONL file
on disk. The file is append-only and suitable for long-term retention.

```bash
export RAUCLE_AUDIT_PERSIST=true
export RAUCLE_AUDIT_LOG=/data/gateway-audit.jsonl
```

The audit log file is rotated manually (copy + truncate) or by an external
log shipper (Filebeat, Fluentd).

## API Key Rotation

Admin panel API keys support optional expiry timestamps. Create a key that
expires in 90 days:

```python
import time

users.add_user("temp-key", "operator", name="Temp", expires_at=time.time() + 86400 * 90)
```

Expired keys are automatically rejected on authentication. The admin panel
shows key creation time and expiry.

## Rate Limiting

The gateway API has built-in rate limiting via slowapi (200 requests/minute
per IP on `/gate`, 1000/minute global default). Caddy provides additional
rate limiting at the reverse proxy layer.

If rate limits are exceeded, the API returns HTTP 429 with a JSON body:
```json
{"detail": "Rate limit exceeded", "retry_after": "60"}
```

## Summary

| Control | Mechanism | Status |
|---|---|---|
| TLS | Caddy + Let's Encrypt | Included |
| Network isolation | Docker internal network | Included |
| Security headers | Caddy | Included |
| Rate limiting | slowapi + Caddy | Included |
| Non-root container | Dockerfile USER raucle | Included |
| Path traversal protection | Policy dir restriction | Included |
| XSS protection | HTML escaping | Included |
| Timing-safe auth | hmac.compare_digest | Included |
| SIEM token redaction | token_configured bool | Included |
| Health check auth | RAUCLE_HEALTH_KEY | Optional |
| Audit log persistence | RAUCLE_AUDIT_PERSIST | Optional |
| API key expiry | expires_at field | Optional |
| WAF | ModSecurity + OWASP CRS | External |
| Secret management | Docker secrets / Vault | External |