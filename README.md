# SQL-Injection-JWT

A hands-on educational lab demonstrating SQL injection vulnerabilities, secure parameterized queries, and JWT token attacks with hardened defenses.

## Quick Start

### Prerequisites
- Node.js (v14+)
- npm
- SQLite3 (optional, bundled via npm)
- Postman (for API testing) or curl
- Wireshark (for traffic capture, optional)

### Local Setup

1. **Navigate to the lab directory:**
   ```bash
   cd "Lab 1"
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up environment variables:**
   ```bash
   cp use.env .env
   ```

4. **Generate strong secrets:**
   ```bash
   node generate-secrets.js
   ```
   Copy the printed `ACCESS_TOKEN_SECRET` and `REFRESH_TOKEN_SECRET` values into your `.env` file. Replace the placeholder values.

5. **Initialize the database:**
   ```bash
   npm run init-db
   ```
   This creates `users.db` with three sample users:
   - `admin` / `admin123`
   - `alice` / `alicepass`
   - `bob` / `bobpass`

6. **Start the server:**
   ```bash
   npm start
   ```
   The server runs at `http://localhost:1234`.

## Environment Configuration

### `.env` File Structure

Create `.env` from `use.env` and fill in the values:

```
# Server configuration
PORT=1234
DB_PATH=./users.db

# Token configuration (generate using node generate-secrets.js)
ACCESS_TOKEN_SECRET=<paste_strong_random_secret_here>
REFRESH_TOKEN_SECRET=<paste_strong_random_secret_here>
WEAK_SECRET=weak_demo_secret

# Token claims and lifetimes
TOKEN_ISSUER=lab-2.example
TOKEN_AUDIENCE=lab-2-students
ACCESS_TOKEN_LIFETIME=15m
REFRESH_TOKEN_LIFETIME=7d
```

**Important:** The `WEAK_SECRET` is intentionally weak for demonstrating attacks. Never use weak secrets in production.

## API Endpoints Reference

### Authentication Endpoints

#### POST /vuln-login
**Vulnerable endpoint** - demonstrates poor security practices.
- Returns tokens signed with `WEAK_SECRET`
- Tokens lack `iss` and `aud` claims
- Uses SQL string concatenation (SQL injection risk)

**Request:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response (Success):**
```json
{
  "success": true,
  "message": "VULN login success for user: admin",
  "accessToken": "eyJhbGc...",
  "refreshToken": "eyJhbGc...",
  "rows": [{"id": 1, "username": "admin", "password": "admin123"}]
}
```

#### POST /login
**Secure endpoint** - demonstrates hardened security practices.
- Tokens signed with strong `ACCESS_TOKEN_SECRET`
- Includes `iss` (issuer) and `aud` (audience) claims
- Uses parameterized SQL queries (SQL injection protected)
- Includes input validation and escaping

**Request:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response (Success):**
```json
{
  "success": true,
  "message": "SECURE login success for user: admin",
  "accessToken": "eyJhbGc...",
  "refreshToken": "eyJhbGc...",
  "user": {"id": 1, "username": "admin"}
}
```

### Protected Endpoints

#### GET /admin/list-users
**Secure protected endpoint** - requires Bearer token.
- Verifies token signature using `ACCESS_TOKEN_SECRET`
- Checks token algorithm (must be HS256)
- Validates `iss` and `aud` claims
- Rejects expired tokens

**Request Header:**
```
Authorization: Bearer <accessToken>
```

**Response:**
```json
{
  "users": [
    {"id": 1, "username": "admin"},
    {"id": 2, "username": "alice"},
    {"id": 3, "username": "bob"}
  ],
  "authorizedUser": "admin"
}
```

#### GET /vuln/admin-list
**Vulnerable protected endpoint** - demonstrates token forgery vulnerability.
- Decodes tokens WITHOUT verifying signature
- Accepts `alg: none` tokens
- Accepts tokens signed with weak secrets
- No issuer or audience validation

**Request Header:**
```
Authorization: Bearer <forgedToken>
```

### Token Management Endpoints

#### POST /token
**Refresh token exchange** - implements refresh token rotation.
- Exchanges valid refresh token for new access token
- Revokes old refresh token (prevents replay)
- Issues new refresh token

**Request:**
```json
{
  "refreshToken": "<refreshToken>"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGc...",
  "refreshToken": "eyJhbGc..."
}
```

#### POST /logout
**Token revocation** - invalidates a refresh token.

**Request:**
```json
{
  "refreshToken": "<refreshToken>"
}
```

**Response:**
```json
{
  "success": true
}
```

## Demonstration: SQL Injection Attack

### Attack Scenario 1: Authentication Bypass

1. **Send vulnerable login request with SQL injection payload:**

   **Using Postman:**
   - Method: POST
   - URL: `http://localhost:1234/vuln-login`
   - Body (JSON):
     ```json
     {
       "username": "admin",
       "password": "' OR '1'='1"
     }
     ```

   **Using curl:**
   ```bash
   curl -X POST http://localhost:1234/vuln-login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"'"'"' OR '"'"'1'"'"'='"'"'1"}'
   ```

2. **Observe the attack:**
   - Check server console output - you'll see the constructed SQL:
     ```sql
     SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';
     ```
   - The condition `'1'='1'` is always true, bypassing authentication
   - The vulnerable endpoint returns the first user (admin) without checking the password

3. **Contrast with secure endpoint:**
   - Send the same request to `/login`
   - The secure endpoint uses parameterized queries:
     ```sql
     SELECT * FROM users WHERE username = ? AND password = ?;
     ```
   - The input is treated as literal data, not SQL code
   - Authentication fails correctly (password doesn't match)

### Attack Scenario 2: Data Extraction via UNION

1. **Send SQL UNION injection payload:**

   ```json
   {
     "username": "admin' UNION SELECT NULL, sqlite_version(), NULL--",
     "password": "anything"
   }
   ```

2. **Observe the attack:**
   - Constructed SQL becomes:
     ```sql
     SELECT * FROM users WHERE username = 'admin' UNION SELECT NULL, sqlite_version(), NULL--' AND password = 'anything';
     ```
   - Returns SQLite version instead of user data
   - Demonstrates information disclosure

## Demonstration: JWT Token Attacks

### Attack 1: Forge Token with Weak Secret

1. **Generate a forged token using forge_token.js:**
   ```bash
   node forge_token.js --alg weak --sub admin
   ```

2. **Use the forged token against vulnerable endpoint:**
   - In Postman, send GET request to `http://localhost:1234/vuln/admin-list`
   - Set Authorization header: `Bearer <forgedToken>`
   - Result: Vulnerable endpoint accepts it (returns user list)

3. **Try against secure endpoint:**
   - Same request to `http://localhost:1234/admin/list-users`
   - Result: Secure endpoint rejects it (token signed with wrong secret)

### Attack 2: alg:none Header Trick

1. **Generate token with alg:none:**
   ```bash
   node forge_token.js --alg none --sub admin
   ```

2. **Use against vulnerable endpoint:**
   - GET `http://localhost:1234/vuln/admin-list`
   - Authorization: `Bearer <noneToken>`
   - Result: Vulnerable endpoint accepts it (no signature verification)

3. **Try against secure endpoint:**
   - Same request to `http://localhost:1234/admin/list-users`
   - Result: Secure endpoint rejects it (algorithm verification fails)

### Attack 3: Token Replay and Expiration

1. **Obtain access token from login:**
   ```bash
   # Login to get tokens
   curl -X POST http://localhost:1234/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}'
   ```

2. **Use token immediately:**
   - GET `/admin/list-users` with valid token
   - Result: Accepted (token valid and not expired)

3. **Wait for token expiration (default 15 minutes):**
   - After 15 minutes, retry with same token
   - Result: Rejected (token expired)

4. **Use refresh token to get new access token:**
   ```bash
   curl -X POST http://localhost:1234/token \
     -H "Content-Type: application/json" \
     -d '{"refreshToken":"<refreshToken>"}'
   ```

## Traffic Capture with Wireshark

### Setup

1. **Start Wireshark:**
   ```bash
   wireshark
   ```

2. **Select interface:**
   - **Linux/Mac:** Select `lo` (loopback) interface
   - **Windows:** Select `Loopback Pseudo-Interface` or `lo`

3. **Start capturing:**
   - Click the play button or press Ctrl+E

### Filters to Use

- **HTTP traffic on port 1234:**
  ```
  tcp.port == 1234
  ```

- **Show only HTTP:**
  ```
  http
  ```

- **Show POST requests:**
  ```
  tcp.port == 1234 && http.request.method == "POST"
  ```

- **Show Authorization headers:**
  ```
  tcp.port == 1234 && http.request.header contains "Authorization"
  ```

### What You'll Observe

- **Vulnerable login:** Password visible in plaintext in POST body
- **SQL injection payload:** Entire query string visible in server logs (check console)
- **Tokens in headers:** Bearer tokens transmitted in Authorization header (unencrypted over HTTP)
- **Token payload:** Base64-encoded JWT can be decoded to see claims

**Note:** This is HTTP (unencrypted). In production, use HTTPS/TLS to encrypt tokens and sensitive data in transit.

## Architecture & Security Comparison

### Vulnerable Path (/vuln-login, /vuln/admin-list)

**SQL Injection:**
```javascript
const sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';";
```
- User input directly concatenated into SQL
- Attacker can inject SQL operators, comments, or subqueries
- No input sanitization

**JWT Issues:**
- Tokens signed with weak secret (easily bruted)
- No issuer/audience claims
- Vulnerable endpoint decodes without verification
- No algorithm validation (accepts `alg:none`)

### Secure Path (/login, /admin/list-users)

**SQL Injection Prevention:**
```javascript
const sql = "SELECT * FROM users WHERE username = ? AND password = ?;";
db.get(sql, [username, password], callback);
```
- Parameterized query with placeholders
- Input treated as literal data, never parsed as SQL
- Database driver handles escaping automatically

**JWT Hardening:**
- Tokens signed with strong secret (48-byte random value)
- Includes `iss` (issuer) and `aud` (audience) claims
- Endpoint verifies signature using correct secret
- Algorithm validation (must be HS256)
- Short-lived access tokens (15 minutes)
- Refresh token rotation (old token revoked)

## Key Assumptions & Limitations

### Assumptions

1. **Single-server deployment:** Refresh token store is in-memory. Distributed systems need persistent storage.
2. **HTTP context:** This lab uses HTTP for simplicity. Production must use HTTPS/TLS.
3. **No rate limiting:** No protection against brute force or replay attacks in this lab.
4. **Plaintext passwords in DB:** Database stores plaintext passwords for demonstration only.
5. **Local database:** SQLite is file-based. Production systems should use PostgreSQL, MySQL, etc.

### Limitations

1. **In-memory token storage:** Tokens are lost if server restarts. Use Redis or database in production.
2. **No token blacklist:** Invalidated tokens aren't checked. Implement a blacklist for logout.
3. **No rate limiting:** Can be brute-forced. Add rate limiting middleware.
4. **No HTTPS:** Tokens visible in plaintext during transmission. Always use TLS in production.
5. **No multi-device support:** Refresh token rotation doesn't account for multiple sessions per user.
6. **Demo secrets:** `WEAK_SECRET` is intentionally weak. Always generate cryptographically secure secrets.

### Troubleshooting

**Native SQLite3 Build Errors:**

If you see errors like `invalid ELF header` or module not found:

```bash
# Rebuild for current platform
npm rebuild

# Or reinstall with source build
npm install --build-from-source sqlite3

# Or clean and reinstall
rm -rf node_modules package-lock.json
npm install
```

**Port Already in Use:**

If port 1234 is occupied, change PORT in `.env`:
```
PORT=3001
```

**Token Decode/Verification Errors:**

Ensure `.env` secrets match what's being used:
- Vulnerable endpoints use `WEAK_SECRET`
- Secure endpoints use `ACCESS_TOKEN_SECRET` and `REFRESH_TOKEN_SECRET`

## Educational Goals

By completing this lab, you will understand:

1. How SQL injection exploits concatenated query strings
2. How parameterized queries prevent SQL injection
3. How JWT tokens are structured and signed
4. Common JWT implementation vulnerabilities (weak secrets, missing claims, no verification)
5. The difference between authentication and authorization
6. Token expiration and refresh token rotation
7. How to capture and analyze HTTP traffic with Wireshark
8. Security hardening techniques for web applications

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP JWT Security](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [Node.js crypto module](https://nodejs.org/api/crypto.html)
- [Express.js Best Practices Security](https://expressjs.com/en/advanced/best-practice-security.html)

## Disclaimer

**This lab is for educational purposes only.** Do not use the techniques demonstrated here for unauthorized access to systems. Always obtain proper authorization before testing security measures. Follow your organization's responsible disclosure policy when reporting vulnerabilities.

## License

Educational/demonstration use only. Not intended for production.
