#!/usr/bin/env python3
"""
Unified Login and LDAP Auth App
- Serves a login form at /login
- Authenticates against LDAP
- Issues a secure session token (stored in-memory)
- Protects endpoints, redirects to login if not authenticated
"""
import sys, os, ldap, uuid, signal, base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs
import threading


# In-memory session store: {uid_uuid_token: (username, created_time)}
import time
import argparse
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()  # Protect session dict from concurrent access
SESSION_COOKIE = 'nginxauth'
SESSION_LIFETIME = 43200  # 12 hours in seconds


# LDAP configuration (can be set via env or CLI)
# Example values:
# LDAP_URL = 'ldap://ldap.example.com:389'
# LDAP_BASEDN = 'dc=example,dc=com'
# LDAP_TEMPLATE = '(uid=%(username)s)'
# LDAP_BINDDN = 'cn=serviceaccount,dc=example,dc=com'
# LDAP_BINDPASS = 'secretpassword'
# LDAP_STARTTLS = 'true'
LDAP_URL = os.environ.get('LDAP_URL', 'ldap://localhost:389')
LDAP_BASEDN = os.environ.get('LDAP_BASEDN', '')
LDAP_TEMPLATE = os.environ.get('LDAP_TEMPLATE', '(uid=%(username)s)')
LDAP_BINDDN = os.environ.get('LDAP_BINDDN', '')
LDAP_BINDPASS = os.environ.get('LDAP_BINDPASS', '')
LDAP_STARTTLS = os.environ.get('LDAP_STARTTLS', 'false')

Listen = ('0.0.0.0', 9000)

class ThreadedHTTPServer(HTTPServer):
    """HTTPServer that handles each request in a separate thread"""
    def process_request(self, request, client_address):
        thread = threading.Thread(target=self.__new_request,
                                 args=(self.RequestHandlerClass, request, client_address, self))
        thread.daemon = True
        thread.start()
    
    def __new_request(self, handlerClass, request, address, server):
        handlerClass(request, address, server)
        self.shutdown_request(request)

class UnifiedHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == '/login':
            # Get target from X-Target header (set by nginx auth_request)
            target = self.headers.get('X-Target')
            return self.serve_login_form(target=target)
        if not self.is_authenticated():
            # Return 401 for nginx auth_request to handle redirect
            # nginx.ingress.kubernetes.io/auth-signin will redirect to login
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Cookie realm="Login Required"')
            self.end_headers()
            return
        # Authenticated: return 200 OK for nginx auth_request
        self.send_response(200)
        self.send_header('X-User', self.get_username())
        self.end_headers()

    def do_POST(self):
        url = urlparse(self.path)
        if url.path == '/login':
            return self.handle_login()
        self.send_response(404)
        self.end_headers()

    def serve_login_form(self, error=None, target=None):
        # If no target, try to get from query string
        if target is None:
            url = urlparse(self.path)
            from urllib.parse import parse_qs
            params = parse_qs(url.query)
            target = params.get('target', ['/'])[0]
        
        # Fallback to root if still no target
        if target is None:
            target = '/'
            
        html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        body {{
            background: #f6f8fa;
            font-family: 'Segoe UI', Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }}
        .login-container {{
            background: #fff;
            padding: 2.5rem 2rem 2rem 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 16px rgba(0,0,0,0.08);
            min-width: 320px;
        }}
        .login-container h2 {{
            margin-top: 0;
            margin-bottom: 1.5rem;
            color: #222;
            font-weight: 600;
            text-align: center;
        }}
        .login-container form {{
            display: flex;
            flex-direction: column;
        }}
        .login-container label {{
            margin-bottom: 0.5rem;
            color: #444;
            font-size: 1rem;
        }}
        .login-container input[type="text"],
        .login-container input[type="password"] {{
            padding: 0.6rem;
            margin-bottom: 1.2rem;
            border: 1px solid #d1d5db;
            border-radius: 5px;
            font-size: 1rem;
            background: #f9fafb;
            transition: border 0.2s;
        }}
        .login-container input[type="text"]:focus,
        .login-container input[type="password"]:focus {{
            border: 1.5px solid #2563eb;
            outline: none;
        }}
        .login-container input[type="submit"] {{
            background: #2563eb;
            color: #fff;
            border: none;
            border-radius: 5px;
            padding: 0.7rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .login-container input[type="submit"]:hover {{
            background: #1d4ed8;
        }}
        .error-message {{
            color: #d32f2f;
            background: #fdecea;
            border: 1px solid #f8bbba;
            border-radius: 5px;
            padding: 0.7rem 1rem;
            margin-bottom: 1.2rem;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Sign in</h2>
        {f'<div class="error-message">{error}</div>' if error else ''}
        <form method="post" action="/login">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" autocomplete="username" required autofocus />
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required />
            <input type="hidden" name="target" value="{target}" />
            <input type="submit" value="Login" />
        </form>
    </div>
</body>
</html>
        '''
        self.send_response(200)
        self.end_headers()
        self.wfile.write(html.encode())

    def handle_login(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length).decode()
        params = parse_qs(data)
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]
        target = params.get('target', ['/'])[0]
        
        if not username or not password:
            return self.serve_login_form(error='Missing username or password', target=target)
        if not self.ldap_auth(username, password):
            return self.serve_login_form(error='Invalid credentials', target=target)
        # Success: create session with uid:uuid format
        uid_uuid_token = f"{username}:{uuid.uuid4()}"
        # Base64 encode the token for cookie storage
        encoded_token = base64.b64encode(uid_uuid_token.encode()).decode()
        now = int(time.time())
        with SESSIONS_LOCK:
            SESSIONS[uid_uuid_token] = (username, now)
        self.send_response(302)
        self.send_header('Set-Cookie', f'{SESSION_COOKIE}={encoded_token}; HttpOnly; Path=/')
        self.send_header('Location', target)
        self.end_headers()

    def ldap_auth(self, username, password):
        """Authenticate user against LDAP server"""
        try:
            self.log_message(f"Attempting LDAP auth for user: {username}")
            ldap_obj = ldap.initialize(LDAP_URL)
            ldap_obj.protocol_version = ldap.VERSION3
            
            # Enable STARTTLS if configured
            if LDAP_STARTTLS.lower() == 'true':
                ldap_obj.start_tls_s()
            
            # Bind as search user if credentials provided
            if LDAP_BINDDN:
                self.log_message(f"Binding as search user: {LDAP_BINDDN}")
                ldap_obj.bind_s(LDAP_BINDDN, LDAP_BINDPASS, ldap.AUTH_SIMPLE)
            
            # Search for user DN
            searchfilter = LDAP_TEMPLATE % {'username': username}
            self.log_message(f"Searching with filter: {searchfilter} in base: {LDAP_BASEDN}")
            results = ldap_obj.search_s(LDAP_BASEDN, ldap.SCOPE_SUBTREE, searchfilter, ['objectclass'], 1)
            
            if not results:
                self.log_error(f"No LDAP results found for user: {username}")
                return False
            
            user_dn = results[0][0]
            if not user_dn:
                self.log_error(f"User DN is None for user: {username}")
                return False
            
            self.log_message(f"Found user DN: {user_dn}, attempting bind")
            # Bind as the user to verify password
            ldap_obj.bind_s(user_dn, password, ldap.AUTH_SIMPLE)
            self.log_message(f"LDAP auth successful for user: {username}")
            return True
        except ldap.INVALID_CREDENTIALS:
            self.log_error(f"Invalid credentials for user: {username}")
            return False
        except ldap.SERVER_DOWN:
            self.log_error(f"LDAP server unavailable: {LDAP_URL}")
            return False
        except Exception as e:
            self.log_error(f"LDAP auth error for user {username}: {type(e).__name__} - {str(e)}")
            return False

    def is_authenticated(self):
        cookie = self.headers.get('Cookie')
        if not cookie:
            return False
        c = SimpleCookie(cookie)
        encoded_token = c.get(SESSION_COOKIE)
        if not encoded_token:
            return False
        
        try:
            # Decode the base64 token
            uid_uuid_token = base64.b64decode(encoded_token.value).decode()
            # Verify format is uid:uuid
            if ':' not in uid_uuid_token:
                return False
            uid, token_uuid = uid_uuid_token.split(':', 1)
            if not uid or not token_uuid:
                return False
        except Exception:
            return False
            
        with SESSIONS_LOCK:
            value = SESSIONS.get(uid_uuid_token)
            if not value:
                return False
            username, created = value
            # Verify the uid matches the stored username
            if uid != username:
                return False
            now = int(time.time())
            if now - created > SESSION_LIFETIME:
                # Session expired, remove it
                del SESSIONS[uid_uuid_token]
                return False
        return True

    def get_username(self):
        cookie = self.headers.get('Cookie')
        if not cookie:
            return ''
        c = SimpleCookie(cookie)
        encoded_token = c.get(SESSION_COOKIE)
        if not encoded_token:
            return ''
        
        try:
            # Decode the base64 token
            uid_uuid_token = base64.b64decode(encoded_token.value).decode()
            # Verify format is uid:uuid
            if ':' not in uid_uuid_token:
                return ''
            uid, token_uuid = uid_uuid_token.split(':', 1)
            if not uid or not token_uuid:
                return ''
        except Exception:
            return ''
            
        with SESSIONS_LOCK:
            value = SESSIONS.get(uid_uuid_token)
            if not value:
                return ''
            username, created = value
            # Verify the uid matches the stored username
            if uid != username:
                return ''
            now = int(time.time())
            if now - created > SESSION_LIFETIME:
                # Session expired, remove it
                del SESSIONS[uid_uuid_token]
                return ''
        return username

    def redirect(self, location):
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Custom log message handler"""
        sys.stdout.write("%s - [%s] %s\n" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args
        ))
        sys.stdout.flush()
    
    def log_error(self, format, *args):
        """Custom error log handler"""
        sys.stderr.write("%s - [%s] ERROR: %s\n" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args
        ))
        sys.stderr.flush()

def exit_handler(signal, frame):
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Unified Login and LDAP Auth App - Presents login page and authenticates via LDAP with session tokens")
    
    # Listen options
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind (Default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=9000, help='Port to bind (Default: 9000)')
    
    # LDAP options
    parser.add_argument('-u', '--url', '--ldap-url', dest='ldap_url',
                        default=os.environ.get('LDAP_URL', 'ldap://localhost:389'),
                        help='LDAP server URI (Default: ldap://localhost:389)')
    parser.add_argument('-b', '--basedn', '--ldap-basedn', dest='ldap_basedn',
                        default=os.environ.get('LDAP_BASEDN', ''),
                        help='LDAP base DN (Default: empty)')
    parser.add_argument('-f', '--filter', '--ldap-template', dest='ldap_template',
                        default=os.environ.get('LDAP_TEMPLATE', '(uid=%(username)s)'),
                        help='LDAP search filter (Default: (uid=%%(username)s))')
    parser.add_argument('-D', '--binddn', '--ldap-binddn', dest='ldap_binddn',
                        default=os.environ.get('LDAP_BINDDN', ''),
                        help='LDAP bind DN for searching (Default: empty/anonymous)')
    parser.add_argument('-w', '--bindpw', '--ldap-bindpass', dest='ldap_bindpass',
                        default=os.environ.get('LDAP_BINDPASS', ''),
                        help='LDAP bind password (Default: empty)')
    parser.add_argument('-s', '--starttls', '--ldap-starttls', dest='ldap_starttls',
                        default=os.environ.get('LDAP_STARTTLS', 'false'),
                        help='Enable STARTTLS (Default: false)')
    
    # Session options
    parser.add_argument('--session-lifetime', type=int, default=43200,
                        help='Session lifetime in seconds (Default: 43200 = 12 hours)')
    parser.add_argument('--session-cookie-name', default='nginxauth',
                        help='Session cookie name (Default: nginxauth)')

    args = parser.parse_args()
    
    # Set global configuration
    LDAP_URL = args.ldap_url
    LDAP_BASEDN = args.ldap_basedn
    LDAP_TEMPLATE = args.ldap_template
    LDAP_BINDDN = args.ldap_binddn
    LDAP_BINDPASS = args.ldap_bindpass
    LDAP_STARTTLS = args.ldap_starttls
    SESSION_LIFETIME = args.session_lifetime
    SESSION_COOKIE = args.session_cookie_name
    Listen = (args.host, args.port)
    
    server = ThreadedHTTPServer(Listen, UnifiedHandler)
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)
    
    print(f"Unified Auth App starting...")
    print(f"  Listening on: {Listen[0]}:{Listen[1]}")
    print(f"  LDAP Server: {LDAP_URL}")
    print(f"  LDAP Base DN: {LDAP_BASEDN or '(not set)'}")
    print(f"  LDAP Bind DN: {LDAP_BINDDN or '(anonymous)'}")
    print(f"  Session Lifetime: {SESSION_LIFETIME} seconds ({SESSION_LIFETIME/3600:.1f} hours)")
    print(f"  Session Cookie: {SESSION_COOKIE}")
    print("Ready to accept connections...")
    sys.stdout.flush()
    
    server.serve_forever()
