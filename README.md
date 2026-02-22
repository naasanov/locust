# uncp

## INF-03 Server Runbook

### 1. Start backend API

```bash
uvicorn server.main:app --reload --port 8000
```

### 2. Check health

```bash
curl http://localhost:8000/api/health
```

### 3. Query assets

```bash
curl "http://localhost:8000/api/assets/<engagement_id>"
```

### 4. Query findings

```bash
curl "http://localhost:8000/api/findings/<engagement_id>"
```

### 5. Query attack chains

```bash
curl "http://localhost:8000/api/chains/<engagement_id>"
```

### 6. Global status

```bash
curl http://localhost:8000/api/status
```

### 7. Run dashboard

```bash
cd frontend
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 NEXT_PUBLIC_ENGAGEMENT_ID=abc123 npm run dev
```
