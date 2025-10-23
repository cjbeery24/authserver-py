# OAuth 2.0 Login UI

A simple, modern frontend implementation for testing OAuth 2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange).

## Features

- ✅ OAuth 2.0 Authorization Code Flow
- ✅ PKCE Support (SHA-256)
- ✅ CSRF Protection with State Parameter
- ✅ Modern, Clean UI
- ✅ Token Display and User Info
- ✅ Responsive Design

## Prerequisites

1. The auth server must be running on `http://localhost:8000`
2. You need to create an OAuth client with the following settings:
   - Redirect URI: `http://localhost:3000/callback.html`
   - Allowed scopes: `openid`, `profile`, `email`

## Setup

### 1. Create an OAuth Client

First, you need to create an admin user and OAuth client. Run these commands from the auth server root:

```bash
# Start the auth server
poetry run python run.py

# In another terminal, create an admin user (if you haven't already)
# Then use the API to create an OAuth client
```

Or use the admin endpoints to create a client via the API.

### 2. Update Configuration

Edit the following files and replace the placeholder values with your actual OAuth client credentials:

**index.html** (lines 46-48):

```javascript
const API_URL = "http://localhost:8000";
const CLIENT_ID = "your-actual-client-id"; // Replace this
const REDIRECT_URI = "http://localhost:3000/callback.html";
```

**callback.html** (lines 36-39):

```javascript
const API_URL = "http://localhost:8000";
const CLIENT_ID = "your-actual-client-id"; // Replace this
const CLIENT_SECRET = "your-actual-client-secret"; // Replace this
const REDIRECT_URI = "http://localhost:3000/callback.html";
```

### 3. Start the Frontend Server

You can use any HTTP server. Here are a few options:

**Option 1: Using Python 3**

```bash
cd frontend
python -m http.server 3000
```

**Option 2: Using Node.js http-server**

```bash
cd frontend
npx http-server -p 3000
```

**Option 3: Using the included server script**

```bash
cd frontend
python serve.py
```

### 4. Access the Application

Open your browser and navigate to:

```
http://localhost:3000
```

## Usage Flow

1. **Home Page** (`index.html`)

   - Click "Login with OAuth" to start the authentication flow
   - The app generates PKCE parameters and redirects to the authorization endpoint

2. **Authorization** (Backend)

   - The auth server validates the request and redirects to the login page

3. **Login Page** (`login.html`)

   - Enter your credentials
   - Review the requested permissions
   - Click "Sign In & Authorize"
   - The app authenticates you and completes the authorization

4. **Callback** (`callback.html`)

   - The app receives the authorization code
   - Exchanges the code for access tokens using PKCE
   - Stores tokens in sessionStorage

5. **Home Page** (After Login)
   - Displays the access token (truncated)
   - Shows decoded ID token claims
   - Fetches and displays user info from the `/oauth/userinfo` endpoint

## Files

- **index.html** - Main landing page and post-login token display
- **login.html** - Login and consent page
- **callback.html** - OAuth callback handler
- **styles.css** - Modern, responsive CSS styling
- **oauth.js** - OAuth flow logic with PKCE support
- **serve.py** - Simple Python HTTP server
- **README.md** - This file

## Security Notes

- **Never expose client secrets in production frontend code!**
  - This demo includes the client secret for testing purposes only
  - In production, use confidential clients for server-side apps or public clients (PKCE-only) for SPAs
- **PKCE** provides additional security even with public clients

- **State parameter** protects against CSRF attacks

- **Tokens are stored in sessionStorage** (cleared when browser closes)

## Troubleshooting

### CORS Errors

Make sure your auth server has CORS enabled for `http://localhost:3000`:

```python
# In your auth server configuration
cors_origins = "http://localhost:3000,http://localhost:8080"
```

### Invalid Client

- Verify your CLIENT_ID and CLIENT_SECRET are correct
- Ensure the OAuth client is active in the database
- Check that the redirect URI matches exactly

### Authentication Fails

- Make sure you have a valid user account
- Check that the auth server is running
- Review the browser console for detailed error messages

## Development

To modify the UI:

1. Edit the HTML/CSS/JS files
2. Refresh your browser (no build step required!)
3. Check the browser console for any errors

## Next Steps

- Implement token refresh flow
- Add token revocation on logout
- Store tokens more securely (e.g., httpOnly cookies via backend)
- Add error handling for expired tokens
- Implement automatic token refresh

## API Endpoints Used

- `GET /oauth/authorize` - Initiate authorization
- `POST /oauth/authorize/complete` - Complete authorization after login
- `POST /oauth/token` - Exchange code for tokens
- `GET /oauth/userinfo` - Get user information
- `POST /api/v1/auth/login` - User authentication

## License

MIT

