#!/usr/bin/env python3
"""
Simple HTTP server for serving the OAuth frontend.

Usage:
    python serve.py [port]

Default port is 3000.
"""

import http.server
import socketserver
import sys
import os

# Get port from command line argument or use default
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 3000

# Change to the directory containing this script
os.chdir(os.path.dirname(os.path.abspath(__file__)))

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler with CORS headers."""
    
    def end_headers(self):
        """Add CORS headers to all responses."""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()
    
    def log_message(self, format, *args):
        """Override to provide cleaner logging."""
        print(f"[{self.log_date_time_string()}] {format % args}")

# Create server
with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
    print(f"🚀 OAuth Frontend Server running at http://localhost:{PORT}/")
    print(f"📁 Serving files from: {os.getcwd()}")
    print(f"\n🔗 Open http://localhost:{PORT}/ in your browser")
    print(f"⚙️  Make sure the auth server is running on http://localhost:8000")
    print(f"\n⏹  Press Ctrl+C to stop the server\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped")
        sys.exit(0)


