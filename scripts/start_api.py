#!/usr/bin/env python3
"""
Start the DNA Blockchain Access System API server
"""

import uvicorn
from api.main import app

if __name__ == "__main__":
    print("🧬 Starting DNA Blockchain Access System API...")
    print("📡 Server will be available at: http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔍 Health Check: http://localhost:8000/health")
    print("\nPress Ctrl+C to stop the server")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )