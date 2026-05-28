# System Control Panel (SCP) — Usage Guide

## Endpoints

### 1. Setup (first run only)

```http
POST /scp/setup
Content-Type: application/json

{ "password": "your-secure-password" }
```

- Only works if SCP has **not** been initialized
- Password must be at least 8 characters
- Returns `403` if already initialized

### 2. Control — Start / Stop / Status

```http
POST /scp/control
Content-Type: application/json

{ "password": "your-password", "action": "stop" }
```

**Actions:**

| Action   | Effect                        |
|----------|-------------------------------|
| `start`  | Enables the entire system     |
| `stop`   | Disables all `/api/*` routes  |
| `status` | Returns current system state   |

### 3. Change Password

```http
POST /scp/change-password
Content-Type: application/json

{ "current_password": "old-password", "new_password": "new-secure-password" }
```

- Requires the current password for authentication
- New password must be at least 8 characters
- Only **1 failed password attempt** allowed per request (immediate 401)
- Password hash is never returned or leaked

## What happens when stopped

All `/api/*` requests return:
```
🚫 System stopped. Please contact developer.
```
(HTTP 503, HTML response)

**Exceptions** (always accessible):
- `/scp/setup`
- `/scp/control`
- `/scp/change-password`
- Static files and frontend routes

## Example workflow

```bash
# Initialize
curl -X POST http://localhost:5000/scp/setup \
  -H "Content-Type: application/json" \
  -d '{"password": "mypassword"}'

# Stop the system
curl -X POST http://localhost:5000/scp/control \
  -H "Content-Type: application/json" \
  -d '{"password": "mypassword", "action": "stop"}'

# Check status
curl -X POST http://localhost:5000/scp/control \
  -H "Content-Type: application/json" \
  -d '{"password": "mypassword", "action": "status"}'

# Start the system again
curl -X POST http://localhost:5000/scp/control \
  -H "Content-Type: application/json" \
  -d '{"password": "mypassword", "action": "start"}'

# Change password
curl -X POST http://localhost:5000/scp/change-password \
  -H "Content-Type: application/json" \
  -d '{"current_password": "mypassword", "new_password": "newstrongpassword"}'
```

## Security notes

- Password is hashed with Werkzeug's `generate_password_hash` (PBKDF2/scrypt) — never stored in plain text
- No SCP endpoints are exposed in the frontend React app
- Error messages are intentionally generic to prevent endpoint enumeration
- Database integrity is preserved — SCP only gates HTTP access, it never modifies queue/barber/shop data
