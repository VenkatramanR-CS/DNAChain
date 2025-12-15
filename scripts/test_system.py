#!/usr/bin/env python3
"""
Test the DNA Blockchain Access System
Comprehensive test of all components
"""

import sys
import os
import json
import time
import base64
import requests

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain.abci_app import DNABlockchainApp
from encryption.aes_crypto import AESCrypto
from encryption.key_manager import KeyManager


def test_blockchain_components():
    """Test blockchain components directly"""
    print("🧪 Testing Blockchain Components...")
    
    app = DNABlockchainApp()
    
    # Test DNA registration
    tx_data = {
        'type': 'register_dna',
        'sender': 'user123',
        'timestamp': int(time.time()),
        'sample_id': 'DNA001',
        'cid': 'QmXoYpizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco',
        'file_hash': 'a' * 64,
        'metadata': {'type': 'saliva', 'collection_date': '2024-01-15'}
    }
    
    tx_json = json.dumps(tx_data).encode('utf-8')
    result = app.deliver_tx(type('MockReq', (), {'tx': tx_json})())
    
    if result.code == 0:
        print("✅ DNA Registration: PASSED")
    else:
        print(f"❌ DNA Registration: FAILED - {result.log}")
    
    # Test NFT minting
    nft_tx = {
        'type': 'mint_nft',
        'sender': 'user123',
        'timestamp': int(time.time()),
        'token_id': 'NFT001',
        'sample_id': 'DNA001',
        'metadata_uri': 'https://example.com/metadata/NFT001.json'
    }
    
    nft_json = json.dumps(nft_tx).encode('utf-8')
    nft_result = app.deliver_tx(type('MockReq', (), {'tx': nft_json})())
    
    if nft_result.code == 0:
        print("✅ NFT Minting: PASSED")
    else:
        print(f"❌ NFT Minting: FAILED - {nft_result.log}")
    
    # Test access request
    access_tx = {
        'type': 'request_access',
        'sender': 'researcher456',
        'timestamp': int(time.time()),
        'sample_id': 'DNA001',
        'purpose': 'Medical research'
    }
    
    access_json = json.dumps(access_tx).encode('utf-8')
    access_result = app.deliver_tx(type('MockReq', (), {'tx': access_json})())
    
    if access_result.code == 0:
        print("✅ Access Request: PASSED")
    else:
        print(f"❌ Access Request: FAILED - {access_result.log}")


def test_encryption():
    """Test encryption functionality"""
    print("\n🔐 Testing Encryption...")
    
    crypto = AESCrypto()
    
    # Test data encryption
    test_data = b"This is sensitive DNA data that needs to be encrypted"
    password = "secure_password_123"
    
    encrypt_result = crypto.encrypt_data(test_data, password)
    
    if encrypt_result['success']:
        print("✅ Data Encryption: PASSED")
        
        # Test decryption
        decrypt_result = crypto.decrypt_data(
            encrypt_result['encrypted_data'],
            encrypt_result['iv'],
            encrypt_result['salt'],
            password
        )
        
        if decrypt_result['success'] and decrypt_result['decrypted_data'] == test_data:
            print("✅ Data Decryption: PASSED")
        else:
            print("❌ Data Decryption: FAILED")
    else:
        print(f"❌ Data Encryption: FAILED - {encrypt_result.get('error')}")


def test_key_management():
    """Test key management"""
    print("\n🔑 Testing Key Management...")
    
    key_manager = KeyManager()
    
    # Test keypair generation
    result = key_manager.generate_user_keypair("test_user", "test_password")
    
    if result['success']:
        print("✅ Keypair Generation: PASSED")
        
        # Test signing
        test_data = b"Test data to sign"
        sign_result = key_manager.sign_data("test_user", test_data, "test_password")
        
        if sign_result['success']:
            print("✅ Data Signing: PASSED")
            
            # Test verification
            verify_result = key_manager.verify_signature(
                "test_user", 
                test_data, 
                sign_result['signature']
            )
            
            if verify_result['success'] and verify_result['valid']:
                print("✅ Signature Verification: PASSED")
            else:
                print("❌ Signature Verification: FAILED")
        else:
            print(f"❌ Data Signing: FAILED - {sign_result.get('error')}")
    else:
        print(f"❌ Keypair Generation: FAILED - {result.get('error')}")


def test_api_endpoints():
    """Test API endpoints"""
    print("\n🌐 Testing API Endpoints...")
    
    base_url = "http://localhost:8000"
    
    try:
        # Test root endpoint
        response = requests.get(f"{base_url}/")
        if response.status_code == 200:
            print("✅ Root Endpoint: PASSED")
        else:
            print(f"❌ Root Endpoint: FAILED - {response.status_code}")
        
        # Test health endpoint
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            health_data = response.json()
            print("✅ Health Endpoint: PASSED")
            print(f"   📊 System Status: {health_data}")
        else:
            print(f"❌ Health Endpoint: FAILED - {response.status_code}")
        
        # Test encryption endpoint
        test_data = base64.b64encode(b"Test DNA data").decode('utf-8')
        encrypt_payload = {
            "file_data": test_data,
            "password": "test_password",
            "filename": "test_dna.txt"
        }
        
        response = requests.post(f"{base_url}/crypto/encrypt", json=encrypt_payload)
        if response.status_code == 200:
            encrypt_result = response.json()
            if encrypt_result['success']:
                print("✅ Encryption Endpoint: PASSED")
                
                # Test decryption endpoint
                decrypt_payload = {
                    "encrypted_data": encrypt_result['encrypted_data'],
                    "iv": encrypt_result['iv'],
                    "salt": encrypt_result['salt'],
                    "password": "test_password"
                }
                
                response = requests.post(f"{base_url}/crypto/decrypt", json=decrypt_payload)
                if response.status_code == 200:
                    decrypt_result = response.json()
                    if decrypt_result['success']:
                        print("✅ Decryption Endpoint: PASSED")
                    else:
                        print(f"❌ Decryption Endpoint: FAILED - {decrypt_result.get('error')}")
                else:
                    print(f"❌ Decryption Endpoint: FAILED - {response.status_code}")
            else:
                print(f"❌ Encryption Endpoint: FAILED - {encrypt_result.get('error')}")
        else:
            print(f"❌ Encryption Endpoint: FAILED - {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ API Server not running. Start it with: python scripts/start_api.py")
    except Exception as e:
        print(f"❌ API Test Error: {str(e)}")


def main():
    """Run all tests"""
    print("🧬 DNA Blockchain Access System - Comprehensive Test Suite")
    print("=" * 60)
    
    test_blockchain_components()
    test_encryption()
    test_key_management()
    test_api_endpoints()
    
    print("\n" + "=" * 60)
    print("🎯 Test Suite Complete!")
    print("\n📋 Next Steps:")
    print("1. Start API server: python scripts/start_api.py")
    print("2. Visit API docs: http://localhost:8000/docs")
    print("3. Test with frontend or Postman")


if __name__ == '__main__':
    main()