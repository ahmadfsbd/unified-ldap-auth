# Unified LDAP Authentication App

A secure, unified authentication application that combines login page presentation and LDAP authentication with session token management.

## Features

- **Session-based Authentication**: Generates secure UUID tokens instead of storing passwords
- **Automatic Session Expiry**: Sessions expire after 12 hours (configurable)
- **LDAP Integration**: Full LDAP authentication with service account support
- **Login Page**: Built-in HTML login form
- **Secure Cookies**: HttpOnly cookies to prevent XSS attacks
- **Flexible Configuration**: Environment variables or command-line arguments
- **STARTTLS Support**: Encrypted LDAP connections
- **Better Logging**: Detailed logging for debugging and monitoring

## Installation

### Docker Build

```bash
cd hgi-apps-auth
docker build -t hgi-apps-auth:latest .
```

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python hgi-apps-auth.py --help
```

### Kubernetes/Docker Compose

```yaml
services:
  hgi-apps-auth:
    image: mercury/hgi-apps-auth:latest
    ports:
      - "9000:9000"
    environment:
      LDAP_URL: ldap://ldap.example.com:389
      LDAP_BASEDN: dc=example,dc=com
```

## Configuration

### Environment Variables

```bash
LDAP_URL=ldap://ldap.example.com:389
LDAP_BASEDN=dc=example,dc=com
LDAP_TEMPLATE=(uid=%(username)s)
LDAP_BINDDN=cn=serviceaccount,dc=example,dc=com
LDAP_BINDPASS=secret
LDAP_STARTTLS=false
```

### Command-Line Arguments

```bash
python hgi-apps-auth.py \
  --host 0.0.0.0 \
  --port 9000 \
  --url ldap://ldap.example.com:389 \
  --basedn "dc=example,dc=com" \
  --binddn "cn=serviceaccount,dc=example,dc=com" \
  --bindpw "secret" \
  --session-lifetime 43200
```

### Docker Run

```bash
docker run -d \
  -p 9000:9000 \
  -e LDAP_URL=ldap://ldap.example.com:389 \
  -e LDAP_BASEDN=dc=example,dc=com \
  -e LDAP_BINDDN=cn=serviceaccount,dc=example,dc=com \
  -e LDAP_BINDPASS=secret \
  hgi-apps-auth:latest
```

Or with command-line overrides:

```bash
docker run -d \
  -p 9000:9000 \
  hgi-apps-auth:latest \
  --url ldap://ldap.example.com:389 \
  --basedn "dc=example,dc=com"
```

## Usage

### Access the Login Page

Navigate to: `http://your-server:9000/login`

### Authentication Flow

1. User visits protected resource
2. App checks for valid session token in cookie
3. If no token or expired → redirect to `/login`
4. User submits credentials
5. App authenticates against LDAP
6. On success → generates session token, sets cookie, redirects
7. Subsequent requests use session token (no LDAP lookup)

### API Endpoints

- `GET /login` - Display login form
- `POST /login` - Process login credentials
- `GET /*` - Any other path (requires authentication)

## Security Features

1. **No Password Storage**: Passwords are never stored, only validated once at login
2. **Session Tokens**: Random UUIDs impossible to guess
3. **HttpOnly Cookies**: Prevents JavaScript access to session tokens
4. **Session Expiry**: Automatic logout after configured time
5. **LDAP Bind Verification**: Password validated by LDAP server itself
6. **STARTTLS Support**: Encrypted LDAP communication

## Configuration Options

| Option | Environment Variable | CLI Flag | Default | Description |
|--------|---------------------|----------|---------|-------------|
| Host | - | `--host` | `0.0.0.0` | Listen address |
| Port | - | `-p`, `--port` | `9000` | Listen port |
| LDAP URL | `LDAP_URL` | `-u`, `--url` | `ldap://localhost:389` | LDAP server URI |
| Base DN | `LDAP_BASEDN` | `-b`, `--basedn` | `` | LDAP base DN |
| Search Filter | `LDAP_TEMPLATE` | `-f`, `--filter` | `(uid=%(username)s)` | LDAP search filter |
| Bind DN | `LDAP_BINDDN` | `-D`, `--binddn` | `` | Service account DN |
| Bind Password | `LDAP_BINDPASS` | `-w`, `--bindpw` | `` | Service account password |
| STARTTLS | `LDAP_STARTTLS` | `-s`, `--starttls` | `false` | Enable STARTTLS |
| Session Lifetime | - | `--session-lifetime` | `43200` | Session duration (seconds) |
| Cookie Name | - | `--session-cookie-name` | `sessionid` | Session cookie name |

## Logging

The app logs to stdout/stderr:

- **INFO**: Authentication attempts, session creation, LDAP queries
- **ERROR**: Authentication failures, LDAP connection issues

Example logs:
```
127.0.0.1 - [28/Oct/2025 10:15:23] Attempting LDAP auth for user: jdoe
127.0.0.1 - [28/Oct/2025 10:15:23] Binding as search user: cn=admin,dc=example,dc=com
127.0.0.1 - [28/Oct/2025 10:15:23] Searching with filter: (uid=jdoe) in base: dc=example,dc=com
127.0.0.1 - [28/Oct/2025 10:15:23] Found user DN: uid=jdoe,ou=users,dc=example,dc=com, attempting bind
127.0.0.1 - [28/Oct/2025 10:15:23] LDAP auth successful for user: jdoe
```

## Troubleshooting

### "LDAP URL is not set" or "LDAP baseDN is not set"
Ensure you've configured LDAP_URL and LDAP_BASEDN via environment variables or CLI flags.

### "LDAP server unavailable"
- Check network connectivity to LDAP server
- Verify LDAP server is running
- Check firewall rules

### "Invalid credentials"
- Verify username and password are correct
- Check LDAP search filter matches your directory structure
- Ensure service account has search permissions

### "No LDAP results found"
- Check LDAP_BASEDN is correct
- Verify LDAP_TEMPLATE filter is appropriate for your directory
- Ensure user exists in the specified base DN
