# QuikChex Attendance Automation API

A streamlined API for automating QuikChex attendance marking with session persistence, OTP email verification, and comprehensive logging.

## 🚀 Features

- **One-Click Attendance Marking** - Mark attendance with a single API call
- **Session Persistence** - Reuse existing sessions to avoid repeated OTP verification
- **Auto OTP Handling** - Automatically fetches and submits OTP from Gmail
- **Event Streams** - Real-time progress updates via Server-Sent Events (SSE)
- **Robust Logging** - User-based logging with filtering and search capabilities

## 📋 Installation

### Prerequisites

- Python 3.8+
- Gmail account with App Password enabled (for OTP retrieval)
- QuikChex account credentials

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/quikchex-attendance-api.git
   cd quikchex-attendance-api
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the server:
   ```bash
   python main.py
   ```

The server will start at `http://localhost:8000` by default.

## 🔌 API Endpoints

### Mark Attendance

```
POST /mark
```

Starts the attendance marking process, with real-time progress updates via SSE.

#### Request Body (JSON)

```json
{
  "user_email": "your.email@gmail.com",
  "quickchex_pass": "your-quickchex-password",
  "gmail_app_password": "your-gmail-app-password",
  "_quikchex_app_session": "existing-session-cookie-if-available",
  "remember_user_token": "existing-remember-token-if-available"
}
```

> **Note:** `_quikchex_app_session` and `remember_user_token` are optional. If provided and valid, the API will skip the OTP verification process.

#### Response

Server-Sent Events stream with the following event types:

- `processing` - Process updates
- `step_success` - Individual step completion
- `step_warning` - Non-critical warnings
- `step_error` - Individual step failures
- `app_success` - Overall success
- `app_error` - Overall failure
- `cookies_update` - Session cookie updates

Example:
```
data: {"status": "processing", "message": "Validating Gmail credentials..."}
data: {"status": "step_success", "message": "Gmail login successful."}
...
data: {"status": "app_success", "message": "✅ Attendance marked successfully! Have a great day!"}
data: {"status": "cookies_update", "message": "Session updated/confirmed after successful attendance.", "cookies": {"_quikchex_app_session": "...", "remember_user_token": "..."}}
```

### Health Check

```
GET /health
```

Returns server health status.

### View Logs

```
GET /logs
```

View and filter application logs.

#### Query Parameters

| Parameter    | Type   | Description                             | Example                 |
|--------------|--------|-----------------------------------------|-------------------------|
| user_email   | string | Filter logs by user email               | user@example.com        |
| level        | string | Filter by log level                     | INFO, DEBUG, ERROR      |
| start_date   | string | Start date in YYYY-MM-DD format         | 2025-05-09              |
| end_date     | string | End date in YYYY-MM-DD format           | 2025-05-10              |
| limit        | number | Maximum number of log entries to return | 100                     |
| format       | string | Response format: text or json           | json                    |

Examples:

```
GET /logs?user_email=user@example.com&level=ERROR
GET /logs?start_date=2025-05-09&end_date=2025-05-10&format=json
GET /logs?limit=50
```

## 📊 Flow Diagram

```
┌─────────────────┐
│ Start Request   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│  Check Session  │─Yes─►  Mark Attendance  │
│   Cookies       │     │  with Session     │
└────────┬────────┘     └──────────────────┘
         │No               │
         ▼                 │Success
┌─────────────────┐        │
│  QuikChex Login │        │
└────────┬────────┘        │
         │                 │
         ▼                 │
┌─────────────────┐        │
│ Request OTP     │        │
└────────┬────────┘        │
         │                 │
         ▼                 │
┌─────────────────┐        │
│ Fetch OTP from  │        │
│ Gmail           │        │
└────────┬────────┘        │
         │                 │
         ▼                 │
┌─────────────────┐        │
│ Submit OTP      │        │
└────────┬────────┘        │
         │                 │
         ▼                 │
┌─────────────────┐        │
│ Mark Attendance │        │
└────────┬────────┘        │
         │                 │
         ▼                 ▼
     ┌───────────────────────┐
     │   Return Session      │
     │   Cookies & Result    │
     └───────────────────────┘
```

## ⚙️ Configuration

The application uses the following configuration:

- **Port:** 8000 by default, can be set via the PORT environment variable
- **Log File:** `quikchex_attendance.log` in the application directory

## 🔍 Troubleshooting

### Common Issues

1. **OTP Not Received**
   - Check Gmail app password is correct
   - Ensure Gmail permissions are set correctly
   - Verify QuikChex is sending OTPs to the specified email

2. **Session Cookies Not Working**
   - Session cookies may have expired (typically valid for 2 weeks)
   - Ensure cookies are properly formatted and not URL-encoded twice

3. **Log Access Issues**
   - Ensure the application has write permissions for the log file
   - Check disk space if logs stop being written

### Debugging

Use the `/logs` endpoint to access detailed debug information.

For more verbose logging, set the environment variable:
```bash
export LOG_LEVEL=DEBUG
```

## 🔒 Security Notes

- Gmail app passwords are used only to access the inbox for OTP verification
- No credentials are stored server-side
- Session cookies are passed through but not stored
- Consider using environment variables for sensitive configuration in production

## 📄 License

MIT License

## 🙏 Acknowledgements

This project uses:
- FastAPI for the API framework
- imaplib for Gmail access
- requests for HTTP interactions

---

Made with ❤️ for automated attendance marking 