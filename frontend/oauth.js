/**
 * OAuth 2.0 Authorization Code Flow with PKCE
 *
 * This module handles the OAuth authorization code flow including:
 * - PKCE code verifier and challenge generation
 * - State parameter generation for CSRF protection
 * - Authorization request initiation
 * - Token exchange
 */

/**
 * Generate a random string for PKCE code verifier or state
 * @param {number} length - Length of the string to generate
 * @returns {string} Random URL-safe string
 */
function generateRandomString(length) {
  const charset =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);

  let result = "";
  for (let i = 0; i < length; i++) {
    result += charset[randomValues[i] % charset.length];
  }
  return result;
}

/**
 * Generate SHA-256 hash and convert to base64url
 * @param {string} plain - Plain text to hash
 * @returns {Promise<string>} Base64url encoded hash
 */
async function sha256(plain) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64urlEncode(hash);
}

/**
 * Base64url encode a buffer
 * @param {ArrayBuffer} buffer - Buffer to encode
 * @returns {string} Base64url encoded string
 */
function base64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Generate PKCE code verifier and challenge
 * @returns {Promise<{verifier: string, challenge: string}>}
 */
async function generatePKCE() {
  const verifier = generateRandomString(128);
  const challenge = await sha256(verifier);
  return { verifier, challenge };
}

/**
 * Initiate OAuth authorization code flow
 * @param {string} apiUrl - Base URL of the OAuth server
 * @param {string} clientId - OAuth client ID
 * @param {string} redirectUri - Callback URL
 * @param {string[]} scopes - Array of requested scopes
 */
async function initiateOAuthFlow(
  apiUrl,
  clientId,
  redirectUri,
  scopes = ["openid", "profile", "email"]
) {
  try {
    // Generate PKCE parameters
    const { verifier, challenge } = await generatePKCE();

    // Generate state for CSRF protection
    const state = generateRandomString(32);

    // Store verifier and state in session storage
    sessionStorage.setItem("pkce_verifier", verifier);
    sessionStorage.setItem("oauth_state", state);

    // Build authorization URL
    const authParams = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(" "),
      state: state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });

    const authUrl = `${apiUrl}/oauth/authorize?${authParams.toString()}`;

    // Redirect to authorization endpoint
    window.location.href = authUrl;
  } catch (error) {
    console.error("Error initiating OAuth flow:", error);
    alert("Failed to initiate OAuth flow: " + error.message);
  }
}

/**
 * Exchange authorization code for tokens
 * @param {string} apiUrl - Base URL of the OAuth server
 * @param {string} clientId - OAuth client ID
 * @param {string} clientSecret - OAuth client secret
 * @param {string} code - Authorization code
 * @param {string} redirectUri - Callback URL
 * @param {string} codeVerifier - PKCE code verifier
 * @returns {Promise<Object>} Token response
 */
async function exchangeCodeForTokens(
  apiUrl,
  clientId,
  clientSecret,
  code,
  redirectUri,
  codeVerifier
) {
  const tokenData = new URLSearchParams({
    grant_type: "authorization_code",
    code: code,
    redirect_uri: redirectUri,
    client_id: clientId,
    client_secret: clientSecret,
    code_verifier: codeVerifier,
  });

  const response = await fetch(`${apiUrl}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: tokenData.toString(),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(
      error.error_description || error.error || "Token exchange failed"
    );
  }

  return await response.json();
}

/**
 * Refresh access token using refresh token
 * @param {string} apiUrl - Base URL of the OAuth server
 * @param {string} clientId - OAuth client ID
 * @param {string} clientSecret - OAuth client secret
 * @param {string} refreshToken - Refresh token
 * @returns {Promise<Object>} Token response
 */
async function refreshAccessToken(
  apiUrl,
  clientId,
  clientSecret,
  refreshToken
) {
  const tokenData = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
  });

  const response = await fetch(`${apiUrl}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: tokenData.toString(),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(
      error.error_description || error.error || "Token refresh failed"
    );
  }

  return await response.json();
}

/**
 * Revoke a token
 * @param {string} apiUrl - Base URL of the OAuth server
 * @param {string} clientId - OAuth client ID
 * @param {string} clientSecret - OAuth client secret
 * @param {string} token - Token to revoke
 * @param {string} tokenTypeHint - Type of token ('access_token' or 'refresh_token')
 * @returns {Promise<void>}
 */
async function revokeToken(
  apiUrl,
  clientId,
  clientSecret,
  token,
  tokenTypeHint = "access_token"
) {
  const credentials = btoa(`${clientId}:${clientSecret}`);

  const formData = new URLSearchParams({
    token: token,
    token_type_hint: tokenTypeHint,
  });

  const response = await fetch(`${apiUrl}/oauth/revoke`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: formData.toString(),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(
      error.error_description || error.error || "Token revocation failed"
    );
  }
}

// Export functions for use in HTML files
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    generateRandomString,
    generatePKCE,
    initiateOAuthFlow,
    exchangeCodeForTokens,
    refreshAccessToken,
    revokeToken,
  };
}

