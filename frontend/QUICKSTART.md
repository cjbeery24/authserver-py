# OAuth Frontend - Quick Start Guide

This guide will help you get the OAuth frontend up and running in just a few minutes.

## Prerequisites

- Auth server running on `http://localhost:8000`
- Database set up and running

## Step 1: Seed the Database

Run the database seeder script to create users, roles, and OAuth clients:

```bash
python scripts/seed_db.py
```

This will create:

- **Users**: `user@example.com` and `admin@example.com` (both with password `Str0ngP@ssw0rd!`)
- **Roles**: `user` and `admin`
- **OAuth Client**: "OAuth Frontend Demo" with proper redirect URIs

The script will output the OAuth client credentials and save them to `frontend/oauth_credentials.txt`.

## Step 2: Update Frontend Configuration

The OAuth credentials will be automatically saved to `frontend/oauth_credentials.txt`. You can either:

### Option A: Manually update the files

Copy the `CLIENT_ID` and `CLIENT_SECRET` from the seeder output or from `frontend/oauth_credentials.txt`, then update:

**frontend/index.html** (around line 48):

```javascript
const CLIENT_ID = "your-client-id-here"; // Replace with actual CLIENT_ID
```

**frontend/callback.html** (around lines 37-38):

```javascript
const CLIENT_ID = "your-client-id-here"; // Replace with actual CLIENT_ID
const CLIENT_SECRET = "your-client-secret-here"; // Replace with actual CLIENT_SECRET
```

### Option B: Use a script to auto-update

Create a simple update script:

```bash
# From the project root
cd frontend
cat oauth_credentials.txt
# Then manually copy the values to the HTML files
```

## Step 3: Start the Frontend Server

```bash
cd frontend
python serve.py
```

Or use Python's built-in HTTP server:

```bash
cd frontend
python -m http.server 3000
```

## Step 4: Start the Auth Server

In a separate terminal:

```bash
poetry run python run.py
```

## Step 5: Test the Flow

1. Open your browser to `http://localhost:3000`
2. Click "Login with OAuth"
3. You'll be redirected to the login page
4. Enter credentials:
   - **Username**: `admin@example.com`
   - **Password**: `Str0ngP@ssw0rd!`
5. Click "Sign In & Authorize"
6. You'll be redirected back with tokens displayed!

## What Happens During the Flow

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │
       │ 1. Click "Login with OAuth"
       │    Generate PKCE verifier/challenge
       │
       ▼
┌─────────────────────┐
│  /oauth/authorize   │  (Auth Server)
│  Validate request   │
└──────┬──────────────┘
       │
       │ 2. Redirect to login page with CSRF token
       │
       ▼
┌─────────────────────┐
│   login.html        │
│  User enters creds  │
└──────┬──────────────┘
       │
       │ 3. POST to /api/v1/auth/login
       │    Authenticate user
       │
       ▼
┌──────────────────────────┐
│  /oauth/authorize/       │
│  complete                │
│  Generate auth code      │
└──────┬───────────────────┘
       │
       │ 4. Redirect to callback with code
       │
       ▼
┌─────────────────────┐
│  callback.html      │
│  Exchange code for  │
│  tokens with PKCE   │
└──────┬──────────────┘
       │
       │ 5. Display tokens and user info
       │
       ▼
┌─────────────┐
│  index.html │
│ (logged in) │
└─────────────┘
```

## Troubleshooting

### CORS Errors

Make sure your `.env` file has:

```env
CORS_ENABLED=true
CORS_ORIGINS=http://localhost:3000,http://localhost:8080
```

### "Invalid client_id"

- Run `python scripts/seed_db.py` again to create the OAuth client
- Check that you've updated the `CLIENT_ID` in both HTML files

### "State mismatch"

- Clear your browser's session storage: Open DevTools → Application → Session Storage → Clear
- Try the flow again

### "Missing PKCE code verifier"

- This usually means you're trying to access the callback directly
- Start from the home page and click "Login with OAuth"

### "User not found"

- Make sure you're using the correct credentials: `admin@example.com` / `Str0ngP@ssw0rd!`
- Check that `python scripts/seed_db.py` completed successfully

## Next Steps

Once the basic flow is working, you can:

- [ ] Implement token refresh
- [ ] Add logout with token revocation
- [ ] Style the UI further
- [ ] Add error handling
- [ ] Implement automatic token refresh before expiry
- [ ] Store tokens more securely (httpOnly cookies via backend proxy)

## Security Notes

⚠️ **Important**: This demo includes the client secret in the frontend JavaScript for testing purposes only. In production:

- **For SPAs**: Use public clients with PKCE (no client secret)
- **For server-side apps**: Keep client secrets on the server
- **Never commit** credentials to version control

## Files Created

```
frontend/
├── index.html           # Main page with OAuth flow initiation
├── login.html           # Login and consent page
├── callback.html        # OAuth callback handler
├── styles.css           # Modern UI styling
├── oauth.js             # OAuth flow logic with PKCE
├── serve.py             # Simple HTTP server
├── oauth_credentials.txt # Generated OAuth credentials
├── README.md            # Detailed documentation
└── QUICKSTART.md        # This file
```

## Support

If you encounter issues:

1. Check the browser console for errors
2. Check the auth server logs
3. Verify all environment variables are set correctly
4. Make sure both servers are running (auth server on 8000, frontend on 3000)

Happy OAuth-ing! 🔐✨

