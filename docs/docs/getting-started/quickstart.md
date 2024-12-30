---
sidebar_position: 1
---

# Quick Start Guide

This guide will help you get started with Cyber AI quickly. Follow these steps to set up and run your first security scan.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cyber-ai.git
cd cyber-ai
```

2. Create a `.env` file with your configuration:
```bash
OPENAI_API_KEY=your_api_key_here
SCAN_TARGET=example.com
```

3. Build the Docker image:
```bash
docker build -t cybersec-mvp .
```

## Running Your First Scan

1. Start the container:
```bash
docker run --env-file .env cybersec-mvp
```

2. Access the web interface at `http://localhost:3000`

3. Log in using your credentials

## Understanding the Dashboard

The dashboard provides several key metrics:

- **Risk Score**: Overall security risk assessment
- **Active Vulnerabilities**: Current security issues
- **Compliance Status**: Regulatory compliance overview
- **Scan History**: Recent scan activities

## Running Different Types of Scans

### Vulnerability Scan
```bash
curl -X POST http://localhost:3000/api/scans/vulnerability \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

### Network Scan
```bash
curl -X POST http://localhost:3000/api/scans/network \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

## Viewing Results

1. Navigate to the Scans page
2. Click on a scan to view detailed results
3. Export results in various formats (PDF, JSON, CSV)

## Next Steps

- Configure [notification settings](../features/notifications)
- Set up [integrations](../features/integrations)
- Learn about [advanced scanning](../features/advanced-scanning)
- Explore [API documentation](../api/overview) 