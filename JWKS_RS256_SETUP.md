# JWKS and RS256 Setup Guide

This guide explains how to set up and use RSA key pairs for JWT signing and the JWKS endpoint for consuming applications.

## Overview

Your auth server now supports **RS256 (RSA + SHA256)** for JWT signing, which provides:

✅ **No shared secrets** - consuming apps only need the public key  
✅ **Industry standard** - JWKS endpoint for key distribution  
✅ **Better security** - private key stays on auth server only  
✅ **Key rotation** - can update keys without touching consuming apps

## Setup Instructions

### 1. Generate RSA Key Pair

Run the key generation script:

```bash
# Generate keys and output as environment variables
python scripts/generate_rsa_keys.py --output-format env

# Or generate keys as PEM files
python scripts/generate_rsa_keys.py --output-format pem

# Generate 4096-bit keys for extra security (optional)
python scripts/generate_rsa_keys.py --key-size 4096
```

### 2. Update Environment Configuration

Copy the generated keys to your `.env` file:

```bash
# Use the example configuration
cp env.example.rs256 .env
# Then edit .env and paste your generated keys
```

Your `.env` should include:

```env
JWT_ALGORITHM=RS256
JWT_KEY_ID=auth-server-key-1
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
[Your private key here]
-----END PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
[Your public key here]
-----END PUBLIC KEY-----"
```

### 3. Install Required Dependencies

Ensure you have the cryptography library:

```bash
poetry add cryptography
# or
pip install cryptography
```

### 4. Restart Your Auth Server

```bash
poetry run python run.py
# or
python run.py
```

### 5. Test the JWKS Endpoint

Visit the JWKS endpoint to verify it's working:

```bash
curl http://localhost:8000/.well-known/jwks.json
```

You should see a response like:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "auth-server-key-1",
      "n": "base64url_encoded_modulus...",
      "e": "AQAB"
    }
  ]
}
```

## Consuming Applications Setup

### Python Example

```python
import jwt
import requests
from cryptography.hazmat.primitives import serialization

class JWTValidator:
    def __init__(self, jwks_url):
        self.jwks_url = jwks_url
        self.public_key = None
        self._load_public_key()

    def _load_public_key(self):
        """Load public key from JWKS endpoint."""
        response = requests.get(self.jwks_url)
        jwks = response.json()

        # Get the first key (you might want to match by kid)
        jwk = jwks["keys"][0]

        # Convert JWK to PEM (simplified - use a proper library like python-jose)
        # For production, use libraries like PyJWT or python-jose with JWKS support
        pass

    def validate_token(self, token):
        """Validate JWT token using public key."""
        try:
            # For now, fetch public key directly from your auth server
            public_key = """-----BEGIN PUBLIC KEY-----
[Your public key here]
-----END PUBLIC KEY-----"""

            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False}  # Adjust based on your needs
            )

            return {
                "user_id": payload["sub"],
                "username": payload["username"],
                "email": payload["email"],
                "valid": True
            }

        except jwt.InvalidTokenError as e:
            return {"valid": False, "error": str(e)}

# Usage
validator = JWTValidator("http://localhost:8000/.well-known/jwks.json")
result = validator.validate_token(your_jwt_token)

if result["valid"]:
    print(f"Hello {result['username']}!")
else:
    print(f"Invalid token: {result['error']}")
```

### Node.js Example

```javascript
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const client = jwksClient({
  jwksUri: "http://localhost:8000/.well-known/jwks.json",
  cache: true,
  cacheMaxAge: 86400 * 1000, // 24 hours
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

function validateToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve({
          userId: decoded.sub,
          username: decoded.username,
          email: decoded.email,
        });
      }
    });
  });
}

// Usage
validateToken(yourJwtToken)
  .then((user) => console.log(`Hello ${user.username}!`))
  .catch((err) => console.log(`Invalid token: ${err.message}`));
```

## Migration from HS256

If you're migrating from HS256, the auth server supports both algorithms:

1. **Gradual migration**: Keep `JWT_SECRET_KEY` for existing tokens
2. **Set algorithm**: `JWT_ALGORITHM=RS256` for new tokens
3. **Consuming apps**: Update to use JWKS endpoint
4. **Remove HMAC**: Once all tokens are RS256, remove `JWT_SECRET_KEY`

## Security Best Practices

### Key Management

- 🔒 **Private key**: Keep secret, never commit to git
- 🔑 **Public key**: Can be shared safely via JWKS
- 💾 **Backup**: Store keys securely for disaster recovery
- 🔄 **Rotation**: Plan for periodic key rotation

### Production Deployment

- Use environment variables or secure key management systems
- Consider using 4096-bit keys for extra security
- Implement key rotation procedures
- Monitor JWKS endpoint availability

### Key Rotation Process

1. Generate new key pair with different `kid`
2. Add new key to JWKS (both keys available)
3. Update auth server to sign with new key
4. Wait for old tokens to expire
5. Remove old key from JWKS

## Troubleshooting

### Common Issues

**"JWKS unavailable - server configuration error"**

- Check that `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` are set
- Verify key format (PEM with proper headers)

**"Invalid signature"**

- Ensure consuming app uses the correct public key
- Check that `kid` matches between token header and JWKS

**"Algorithm mismatch"**

- Verify `JWT_ALGORITHM=RS256` in auth server config
- Ensure consuming app expects RS256 algorithm

### Testing Commands

```bash
# Test JWKS endpoint
curl http://localhost:8000/.well-known/jwks.json

# Test OpenID Connect discovery
curl http://localhost:8000/.well-known/openid_configuration

# Generate a test token and decode it
# (Use your auth server's login endpoint to get a real token)
```

## Benefits Summary

✅ **Security**: No shared secrets between services  
✅ **Scalability**: Consuming apps verify tokens locally  
✅ **Standards**: OpenID Connect / OAuth 2.0 compliant  
✅ **Flexibility**: Easy key rotation without app updates  
✅ **Performance**: Local verification is fast  
✅ **Audit**: Clear separation of public/private keys
