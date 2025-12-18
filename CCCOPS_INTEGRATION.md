# HelpDesk Pro + cccops.com Integration

## Overview

HelpDesk Pro now serves as the contact management system for Triple C Consulting's website (cccops.com).

---

## How It Works

```
Customer visits cccops.com
        ↓
Fills out contact form
        ↓
JavaScript POSTs to /api/public/contact
        ↓
HelpDesk Pro creates ticket (TKT-YYYYMMDD-XXX)
        ↓
Customer sees confirmation with ticket number
        ↓
Ticket appears in HelpDesk Pro dashboard
        ↓
Team responds through HelpDesk Pro
```

---

## API Endpoints Added

### Public (No Auth Required)

**POST /api/public/contact**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "organization": "Company Name",
  "message": "I'd like to learn more..."
}
```

Response:
```json
{
  "success": true,
  "message": "Thank you for contacting us! We will respond within 24 hours.",
  "ticket_number": "TKT-20251217-001"
}
```

**GET /api/public/health**
```json
{
  "status": "healthy",
  "service": "HelpDesk Pro",
  "timestamp": "2025-12-17T21:17:30.071638"
}
```

---

## Security Features

| Feature | Description |
|---------|-------------|
| Rate Limiting | 5 requests per IP per hour |
| Honeypot | Hidden field catches bots |
| CORS | Only allows cccops.com origins |
| Input Validation | Email format, required fields, length limits |
| Audit Logging | All submissions logged with IP |

---

## Custom Domain

| Domain | Points To |
|--------|-----------|
| support.cccops.com | helpdeskpro-oahd.onrender.com |

Configured via GoDaddy DNS CNAME record.

---

## Files Changed

- `app.py` - Added ~190 lines for public contact API
- `requirements.txt` - Added `Flask-Cors==4.0.0`

---

## Testing

```bash
# Health check
curl https://support.cccops.com/api/public/health

# Submit test contact
curl -X POST https://support.cccops.com/api/public/contact \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@example.com","message":"Test message"}'
```

---

## Viewing Submissions

1. Go to https://support.cccops.com/login
2. Login with admin credentials
3. View tickets - website contacts show as "Website Contact: [Name]"
4. Category: General
5. Location: Website

---

## Maintenance

The public API is self-contained and doesn't affect existing HelpDesk functionality. Rate limit data is in-memory and resets on server restart.

To adjust rate limits, modify in `app.py`:
```python
check_rate_limit(ip, max_requests=5, window_seconds=3600)
```
