# Static Code Scanner

A complete **static codebase scanning system** built with **FastAPI + PostgreSQL**.

## Features (as per requirements)

| Feature | Description |
|---------|-------------|
| **Auth (JWT)** | Super Admin → Organizations → Projects hierarchy |
| **ZIP Upload** | Upload project as `.zip` – scan **without running** the code |
| **1. Language Detection** | Detects languages by extension + content heuristics |
| **2. System Analysis** | Structure, dependency files, entry points, frameworks, tests, Docker, CI |
| **3. Secret / Variables** | Finds API keys, passwords, tokens, private keys, connection strings |
| **4. Static Audit** | Security smells (eval, shell=True, XSS, weak crypto, SQL concat, etc.) |
| **No AI** | Pure rule-based scanning |
| **No external analysis libraries** | All rules implemented in pure Python |

## Tech Stack

- **FastAPI** – API
- **PostgreSQL** – Database
- **SQLAlchemy** – ORM
- **JWT** (python-jose) – Authentication
- **Pure Python** – Scanner engine (no Bandit, Semgrep, ESLint, etc.)

## Quick Start

### 1. Prerequisites

- Python 3.10+
- PostgreSQL running

### 2. Setup Database

```bash
# Create database
createdb static_scanner
# Or via psql:
# CREATE DATABASE static_scanner;
```

### 3. Install & Configure

```bash
cd static_scanner
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your DATABASE_URL and SECRET_KEY
```

### 4. Run

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open: http://localhost:8000/docs

**Default Super Admin** (created automatically on first run):

- Email: `admin@scanner.local`
- Password: `admin123`

## API Flow

```
1. Login  →  POST /api/auth/login  (or /login-json)
2. Create Organization  →  POST /api/organizations/   (Super Admin)
3. Create Project       →  POST /api/projects/
4. Upload ZIP & Scan    →  POST /api/scans/project/{project_id}/upload
5. Get Scan Result      →  GET  /api/scans/{scan_id}
```

### Example with curl

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login-json \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@scanner.local","password":"admin123"}' | jq -r .access_token)

# Create Organization
curl -X POST http://localhost:8000/api/organizations/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Corp","description":"Demo org"}'

# Create Project (use org id from previous response)
curl -X POST http://localhost:8000/api/projects/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My App","description":"Demo project","organization_id":1}'

# Upload ZIP and start scan
curl -X POST http://localhost:8000/api/scans/project/1/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/your-project.zip"

# Check scan status & results
curl http://localhost:8000/api/scans/1 \
  -H "Authorization: Bearer $TOKEN"
```

## Scan Result Structure

```json
{
  "id": 1,
  "status": "completed",
  "results": {
    "primary_language": "Python",
    "languages": {"Python": 42, "JavaScript": 10},
    "system_info": {
      "dependency_files": ["requirements.txt"],
      "framework_hints": ["FastAPI"],
      "has_tests": true,
      "has_docker": false
    },
    "secrets_count": 2,
    "secrets_found": [...],
    "static_audit": [
      {
        "id": "SA001",
        "severity": "high",
        "file": "app/utils.py",
        "line": 15,
        "message": "Use of eval() – code injection risk"
      }
    ],
    "audit_score": 78.5,
    "summary": {...}
  }
}
```

## Project Structure

```
static_scanner/
├── app/
│   ├── api/           # Auth, Orgs, Projects, Scans, Users
│   ├── core/          # Config, DB, Security
│   ├── models/        # SQLAlchemy models
│   ├── schemas/       # Pydantic schemas
│   ├── services/
│   │   └── scanner.py # Pure Python static scanner
│   └── main.py
├── requirements.txt
├── .env.example
└── README.md
```

## Notes

- Scanning is **static only** – code is never executed.
- Secrets are **redacted** in results.
- Background tasks handle long scans.
- Zip-slip protection is implemented.
- Max upload size configurable via `MAX_UPLOAD_SIZE_MB`.
