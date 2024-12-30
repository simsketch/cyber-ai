---
sidebar_position: 1
---

# API Overview

Cyber AI provides a comprehensive REST API that allows you to integrate security scanning capabilities into your applications and workflows.

## Authentication

All API requests must include your API key in the Authorization header:

```bash
Authorization: Bearer YOUR_API_KEY
```

## Base URL

```
https://api.cyberai.com/v1
```

## Rate Limiting

- 100 requests per minute for standard plans
- 1000 requests per minute for enterprise plans

## Common Response Codes

- `200`: Success
- `201`: Resource created
- `400`: Bad request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not found
- `429`: Too many requests
- `500`: Internal server error

## Available Endpoints

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/scans` | List all scans |
| POST | `/scans` | Create a new scan |
| GET | `/scans/{id}` | Get scan details |
| DELETE | `/scans/{id}` | Cancel a scan |

### Vulnerabilities

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vulnerabilities` | List all vulnerabilities |
| GET | `/vulnerabilities/{id}` | Get vulnerability details |
| PATCH | `/vulnerabilities/{id}` | Update vulnerability status |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/reports` | List all reports |
| POST | `/reports` | Generate a new report |
| GET | `/reports/{id}` | Get report details |
| GET | `/reports/{id}/download` | Download report |

## Example Request

```bash
curl -X POST https://api.cyberai.com/v1/scans \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "vulnerability",
    "options": {
      "depth": 3,
      "concurrent": 2
    }
  }'
```

## Example Response

```json
{
  "id": "scan_123abc",
  "status": "running",
  "target": "example.com",
  "scan_type": "vulnerability",
  "created_at": "2024-01-20T10:00:00Z",
  "estimated_completion": "2024-01-20T10:05:00Z",
  "progress": {
    "current": 0,
    "total": 100,
    "status": "Initializing scan..."
  }
}
```

## Websocket API

For real-time updates, connect to our WebSocket endpoint:

```javascript
const ws = new WebSocket('wss://api.cyberai.com/v1/ws?token=YOUR_API_KEY')

ws.onmessage = (event) => {
  const data = JSON.parse(event.data)
  console.log('Received update:', data)
}
```

## Error Handling

All errors follow this format:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Invalid scan configuration",
    "details": {
      "field": "target",
      "reason": "Must be a valid domain name"
    }
  }
}
```

## SDKs and Libraries

- [Python SDK](https://github.com/cyberai/python-sdk)
- [JavaScript SDK](https://github.com/cyberai/js-sdk)
- [Go SDK](https://github.com/cyberai/go-sdk)

## Rate Limiting Headers

Response headers include rate limiting information:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1516131012
``` 