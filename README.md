# uncp

## REC-04 Wiring Runbook

### 1. Start backend API

```bash
uvicorn src.api.app:app --reload --port 8000
```

### 2. Trigger a recon cycle

```bash
curl -X POST http://localhost:8000/api/recon/run \
  -H "Content-Type: application/json" \
  -d '{
    "scope": {
      "engagement_id": "abc123",
      "customer": "Acme Corp",
      "targets": {
        "domains": ["acmecorp.com"],
        "ip_ranges": ["203.0.113.10"],
        "cloud_accounts": []
      },
      "forbidden_spec": {
        "forbidden_hosts": [],
        "forbidden_actions": [],
        "tier_limit": 2
      },
      "constraints": {
        "active_hours": {
          "timezone": "UTC",
          "windows": [{"days": ["mon"], "start": "00:00", "end": "23:59"}]
        },
        "cycle_interval_hours": 24,
        "expires_at": "2026-06-01T00:00:00Z",
        "monthly_fee_usdc": 500
      }
    }
  }'
```

### 3. Verify assets in DB/API

```bash
curl "http://localhost:8000/api/assets?engagement_id=abc123&min_score=0.0"
```

### 4. Run dashboard

```bash
cd frontend
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 NEXT_PUBLIC_ENGAGEMENT_ID=abc123 npm run dev
```
