#!/usr/bin/env python3
"""
Start the Complete DNA Blockchain Access System
Launches all components: API server, frontend server, and system monitoring
"""

import os
import sys
import time
import subprocess
import threading
import webbrowser
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.main import app
import uvicorn


class SystemLauncher:
    """Launches and manages the complete DNA blockchain system"""
    
    def __init__(self):
        self.processes = []
        self.api_port = 8000
        self.frontend_port = 8080
        
    def check_dependencies(self):
        """Check if all required dependencies are available"""
        print("🔍 Checking system dependencies...")
        
        # Check Python packages
        required_packages = [
            'fastapi', 'uvicorn', 'cryptography', 'abci', 'requests'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
                print(f"  ✅ {package}")
            except ImportError:
                missing_packages.append(package)
                print(f"  ❌ {package}")
        
        if missing_packages:
            print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
            print("📦 Install with: pip install -r requirements.txt")
            return False
        
        # Check optional dependencies
        optional_packages = ['firebase_admin', 'google.cloud.firestore']
        for package in optional_packages:
            try:
                __import__(package)
                print(f"  ✅ {package} (optional)")
            except ImportError:
                print(f"  ⚠️  {package} (optional - will run in simulation mode)")
        
        print("✅ Dependency check complete!")
        return True
    
    def start_api_server(self):
        """Start the FastAPI server"""
        print(f"🚀 Starting API server on port {self.api_port}...")
        
        def run_api():
            uvicorn.run(
                "api.main:app",
                host="0.0.0.0",
                port=self.api_port,
                reload=False,
                log_level="info"
            )
        
        api_thread = threading.Thread(target=run_api, daemon=True)
        api_thread.start()
        
        # Wait for API to start
        time.sleep(3)
        
        # Test API connection
        try:
            import requests
            response = requests.get(f"http://localhost:{self.api_port}/health", timeout=5)
            if response.status_code == 200:
                print("✅ API server started successfully!")
                return True
            else:
                print(f"❌ API server responded with status {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Failed to connect to API server: {e}")
            return False
    
    def start_frontend_server(self):
        """Start a simple HTTP server for the frontend"""
        print(f"🌐 Starting frontend server on port {self.frontend_port}...")
        
        frontend_dir = Path(__file__).parent.parent / "frontend"
        
        def run_frontend():
            try:
                # Try to use Python's built-in HTTP server
                os.chdir(frontend_dir)
                subprocess.run([
                    sys.executable, "-m", "http.server", str(self.frontend_port)
                ], check=True)
            except Exception as e:
                print(f"❌ Frontend server failed: {e}")
        
        frontend_thread = threading.Thread(target=run_frontend, daemon=True)
        frontend_thread.start()
        
        # Wait for frontend to start
        time.sleep(2)
        
        # Test frontend connection
        try:
            import requests
            response = requests.get(f"http://localhost:{self.frontend_port}", timeout=5)
            if response.status_code == 200:
                print("✅ Frontend server started successfully!")
                return True
            else:
                print(f"⚠️  Frontend server responded with status {response.status_code}")
                return True  # Still consider it successful
        except Exception as e:
            print(f"⚠️  Frontend server check failed: {e}")
            return True  # Still consider it successful
    
    def run_system_tests(self):
        """Run basic system tests"""
        print("🧪 Running system tests...")
        
        try:
            # Import and run test functions
            from scripts.test_system import (
                test_blockchain_components,
                test_encryption,
                test_key_management,
                test_api_endpoints
            )
            
            tests = [
                ("Blockchain Components", test_blockchain_components),
                ("Encryption", test_encryption),
                ("Key Management", test_key_management),
                ("API Endpoints", test_api_endpoints)
            ]
            
            passed = 0
            for test_name, test_func in tests:
                try:
                    if test_func():
                        print(f"  ✅ {test_name}")
                        passed += 1
                    else:
                        print(f"  ❌ {test_name}")
                except Exception as e:
                    print(f"  ❌ {test_name}: {e}")
            
            print(f"📊 Tests passed: {passed}/{len(tests)}")
            return passed == len(tests)
            
        except Exception as e:
            print(f"❌ System tests failed: {e}")
            return False
    
    def open_browser(self):
        """Open the system in the default browser"""
        print("🌐 Opening system in browser...")
        
        urls = [
            f"http://localhost:{self.frontend_port}",
            f"http://localhost:{self.api_port}/docs"
        ]
        
        for url in urls:
            try:
                webbrowser.open(url)
                time.sleep(1)
            except Exception as e:
                print(f"⚠️  Could not open {url}: {e}")
    
    def display_system_info(self):
        """Display system information and URLs"""
        print("\n" + "="*60)
        print("🧬 DNA BLOCKCHAIN ACCESS SYSTEM - RUNNING")
        print("="*60)
        print(f"🌐 Frontend Application: http://localhost:{self.frontend_port}")
        print(f"📡 API Server: http://localhost:{self.api_port}")
        print(f"📚 API Documentation: http://localhost:{self.api_port}/docs")
        print(f"🔍 Health Check: http://localhost:{self.api_port}/health")
        print(f"📊 System Status: http://localhost:{self.api_port}/system/full-status")
        print("\n🎯 Available Features:")
        print("  • DNA Sample Upload & Management")
        print("  • NFT Minting & Trading")
        print("  • Access Control & Permissions")
        print("  • Zero-Knowledge Proof Generation")
        print("  • Encrypted File Storage")
        print("  • Digital Signatures & Key Management")
        print("  • Firebase Integration (simulated)")
        print("  • Real-time System Monitoring")
        print("\n💡 Quick Actions:")
        print("  • Upload DNA Sample: Frontend > DNA Samples > Upload")
        print("  • Generate ZK Proof: Frontend > Zero-Knowledge > Generate")
        print("  • View API Docs: Visit /docs endpoint")
        print("  • Run Tests: python scripts/test_system.py")
        print("\n🛑 To stop the system: Press Ctrl+C")
        print("="*60)
    
    def start_system(self):
        """Start the complete system"""
        print("🧬 DNA Blockchain Access System - Full System Launcher")
        print("="*60)
        
        # Check dependencies
        if not self.check_dependencies():
            print("❌ Dependency check failed. Please install required packages.")
            return False
        
        # Start API server
        if not self.start_api_server():
            print("❌ Failed to start API server")
            return False
        
        # Start frontend server
        if not self.start_frontend_server():
            print("❌ Failed to start frontend server")
            return False
        
        # Run system tests
        if not self.run_system_tests():
            print("⚠️  Some system tests failed, but continuing...")
        
        # Display system information
        self.display_system_info()
        
        # Open browser
        self.open_browser()
        
        # Keep the system running
        try:
            print("\n🔄 System is running... Press Ctrl+C to stop")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down system...")
            return True
    
    def cleanup(self):
        """Clean up processes and resources"""
        for process in self.processes:
            try:
                process.terminate()
            except:
                pass


def main():
    """Main entry point"""
    launcher = SystemLauncher()
    
    try:
        success = launcher.start_system()
        if success:
            print("✅ System shutdown complete")
        else:
            print("❌ System startup failed")
            sys.exit(1)
    except Exception as e:
        print(f"❌ System error: {e}")
        sys.exit(1)
    finally:
        launcher.cleanup()


if __name__ == "__main__":
    main()