# API Examples

## Escalation

```bash
curl -s http://localhost:8002/escalate \
  -H "content-type: application/json" \
  -d '{"ip":"203.0.113.10","path":"/wp-admin","method":"GET","user_agent":"python-requests/2.32"}'
```

## AI Webhook

When `WEBHOOK_SHARED_SECRET` is set, sign the raw JSON body with HMAC-SHA256 and
send the hex digest in `X-Signature`.

```bash
curl -s http://localhost:8001/webhook \
  -H "content-type: application/json" \
  -d '{"action":"block_ip","ip":"203.0.113.10","reason":"test"}'
```

## Tarpit

```bash
curl -s http://localhost:8003/tarpit/page/example.html
```

