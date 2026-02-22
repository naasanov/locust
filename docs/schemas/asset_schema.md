# Asset Output Schema

**Version:** 1.0.0
**Status:** Draft — Pending P3 acknowledgment
**Last Updated:** 2026-02-21

## Overview

This document defines the output schema for assets discovered by the Recon Agent. All five recon tools contribute to building this structure. Gemini Flash scores each asset at the end of the pipeline.

## Schema Definition

```json
{
  "engagement_id": "string",
  "asset_type": "host | web_app | subdomain",
  "ip": "string | null",
  "url": "string | null",
  "open_ports": [443, 22, 80],
  "services": [{"port": 443, "service": "nginx", "version": "1.24"}],
  "endpoints": ["/admin", "/api/v1/users"],
  "exposed_files": [{"path": "/.env", "size": 1024}],
  "shodan_vulns": ["CVE-2021-44228"],
  "attack_surface_score": 0.84
}
```

## Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `engagement_id` | string | Yes | Links asset to the parent engagement |
| `asset_type` | enum | Yes | One of: `host`, `web_app`, `subdomain` |
| `ip` | string \| null | No | IPv4 or IPv6 address (null for unresolved subdomains) |
| `url` | string \| null | No | Full URL for web_app assets |
| `open_ports` | number[] | No | List of open TCP ports discovered by nmap |
| `services` | Service[] | No | Service fingerprints from nmap/banner grabbing |
| `endpoints` | string[] | No | Discovered HTTP endpoints from crawling |
| `exposed_files` | ExposedFile[] | No | Sensitive files found (e.g., `.env`, `.git/config`) |
| `shodan_vulns` | string[] | No | CVE IDs from Censys lookup (legacy field name) |
| `attack_surface_score` | float | Yes | 0.0 - 1.0 score from Gemini Flash |

## Nested Types

### Service

```json
{
  "port": 443,
  "service": "nginx",
  "version": "1.24"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `port` | number | TCP port number |
| `service` | string | Service name (e.g., nginx, ssh, mysql) |
| `version` | string \| null | Version string if detected |

### ExposedFile

```json
{
  "path": "/.env",
  "size": 1024
}
```

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | URL path to the exposed file |
| `size` | number \| null | File size in bytes if available |

## MongoDB Collection

Assets are stored in the `assets` collection with additional metadata:

```json
{
  "_id": "ObjectId",
  "engagement_id": "abc123",
  "asset_type": "web_app",
  "ip": "203.0.113.50",
  "url": "https://acmecorp.com",
  "open_ports": [80, 443, 22],
  "services": [
    {"port": 443, "service": "nginx", "version": "1.24.0"},
    {"port": 22, "service": "openssh", "version": "8.9"}
  ],
  "endpoints": ["/admin", "/api/v1/users", "/wp-admin"],
  "exposed_files": [
    {"path": "/.env", "size": 1024},
    {"path": "/.git/config", "size": 512}
  ],
  "shodan_vulns": ["CVE-2021-44228"],
  "attack_surface_score": 0.84,
  "_metadata": {
    "discovered_at": "2026-02-21T22:30:00Z",
    "last_seen": "2026-02-21T22:30:00Z",
    "recon_cycle": 1,
    "tool_sources": ["nmap", "crawl", "censys"]
  }
}
```

## Tool Contributions

Each recon tool populates specific fields:

| Tool | Fields Populated |
|------|------------------|
| `run_nmap` | `ip`, `open_ports`, `services` |
| `enumerate_subdomains` | Creates new assets with `asset_type: subdomain` |
| `crawl_endpoints` | `url`, `endpoints` |
| `check_exposed_files` | `exposed_files` |
| `censys_lookup` | `shodan_vulns`, additional `services` |
| `gemini_scorer` | `attack_surface_score` |

## Indexing Strategy

```javascript
// MongoDB indexes for the assets collection
db.assets.createIndex({ "engagement_id": 1 })
db.assets.createIndex({ "ip": 1 })
db.assets.createIndex({ "url": 1 })
db.assets.createIndex({ "attack_surface_score": -1 })
db.assets.createIndex({ "_metadata.discovered_at": -1 })
```

## Validation Rules

1. `engagement_id` must exist in the `engagements` collection
2. `attack_surface_score` must be between 0.0 and 1.0
3. At least one of `ip` or `url` must be non-null
4. `asset_type` must be one of the allowed enum values

## Changelog

- **1.0.0** (2026-02-21): Initial schema definition for P3 review
