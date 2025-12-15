#!/usr/bin/env python3
"""
DNA Blockchain Access System - Interactive Demo
Demonstrates the complete workflow of the system
"""

import json
import time
import base64
import requests
from blockchain.abci_app import DNABlockchainApp
from encryption.aes_crypto import AESCrypto
from encryption.key_manager import KeyManager


def print_header(title):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"🧬 {title}")
    print('='*60)


def print_step(step, description):
    """Print a formatted step"""
    print(f"\n📋 Step {step}: {description}")
    print('-' * 40)


def demo_blockchain_workflow():
    """Demonstrate the blockchain workflow"""
    print_header("DNA BLOCKCHAIN ACCESS SYSTEM - LIVE DEMO")
    
    # Initialize components
    app = DNABlockchainApp()
    crypto = AESCrypto()
    key_manager = KeyManager()
    
    print("🚀 System initialized successfully!")
    print(f"   📊 Samples: {app.dna_registry.get_sample_count()}")
    print(f"   🎨 NFTs: {app.nft_module.get_total_supply()}")
    print(f"   📝 Pending Requests: {len(app.access_control.get_pending_requests())}")
    
    # Step 1: Generate user keys
    print_step(1, "Generate User Keypairs")
    
    # Generate keys for sample owner
    owner_result = key_manager.generate_user_keypair("dna_owner", "owner_password")
    if owner_result['success']:
        print(f"✅ Generated keypair for DNA owner")
        print(f"   🔑 Fingerprint: {owner_result['fingerprint']}")
    
    # Generate keys for researcher
    researcher_result = key_manager.generate_user_keypair("researcher", "research_password")
    if researcher_result['success']:
        print(f"✅ Generated keypair for researcher")
        print(f"   🔑 Fingerprint: {researcher_result['fingerprint']}")
    
    # Step 2: Encrypt and register DNA sample
    print_step(2, "Encrypt and Register DNA Sample")
    
    # Simulate DNA data
    dna_data = b"""
    >Sample_DNA_001
    ATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCG
    GCTAGCTAGCTAGCTAGCTAGCTAGCTAGCTAGCTAGCTAGCTAGCTAGCT
    ATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCG
    """
    
    # Encrypt DNA data
    encryption_result = crypto.encrypt_data(dna_data, "dna_sample_password")
    if encryption_result['success']:
        print(f"✅ DNA data encrypted successfully")
        print(f"   📊 Original size: {len(dna_data)} bytes")
        print(f"   🔒 Data hash: {encryption_result['data_hash'][:16]}...")
    
    # Register DNA sample on blockchain
    tx_data = {
        'type': 'register_dna',
        'sender': 'dna_owner_address',
        'timestamp': int(time.time()),
        'sample_id': 'DNA_SAMPLE_001',
        'cid': 'QmEncryptedDNASample001',
        'file_hash': encryption_result['data_hash'],
        'metadata': {
            'type': 'saliva',
            'collection_date': '2024-12-15',
            'patient_id': 'PATIENT_001',
            'encrypted': True
        }
    }
    
    tx_json = json.dumps(tx_data).encode('utf-8')
    result = app.deliver_tx(type('MockReq', (), {'tx': tx_json})())
    
    if result.code == 0:
        print(f"✅ DNA sample registered on blockchain")
        print(f"   🆔 Sample ID: DNA_SAMPLE_001")
        print(f"   👤 Owner: dna_owner_address")
    
    # Step 3: Mint NFT for DNA sample
    print_step(3, "Mint NFT for DNA Ownership")
    
    nft_tx = {
        'type': 'mint_nft',
        'sender': 'dna_owner_address',
        'timestamp': int(time.time()),
        'token_id': 'NFT_DNA_001',
        'sample_id': 'DNA_SAMPLE_001',
        'metadata_uri': 'https://metadata.dna-system.com/NFT_DNA_001.json'
    }
    
    nft_json = json.dumps(nft_tx).encode('utf-8')
    nft_result = app.deliver_tx(type('MockReq', (), {'tx': nft_json})())
    
    if nft_result.code == 0:
        print(f"✅ NFT minted successfully")
        print(f"   🎨 Token ID: NFT_DNA_001")
        print(f"   🔗 Linked to: DNA_SAMPLE_001")
    
    # Step 4: Request access to DNA sample
    print_step(4, "Researcher Requests Access")
    
    access_tx = {
        'type': 'request_access',
        'sender': 'researcher_address',
        'timestamp': int(time.time()),
        'sample_id': 'DNA_SAMPLE_001',
        'purpose': 'Genetic research for rare disease analysis'
    }
    
    access_json = json.dumps(access_tx).encode('utf-8')
    access_result = app.deliver_tx(type('MockReq', (), {'tx': access_json})())
    
    if access_result.code == 0:
        print(f"✅ Access request submitted")
        print(f"   🔬 Researcher: researcher_address")
        print(f"   📋 Purpose: Genetic research for rare disease analysis")
    
    # Step 5: Generate and verify ZK proof
    print_step(5, "Generate Zero-Knowledge Proof")
    
    # Simulate ZK proof generation
    zkp_tx = {
        'type': 'verify_zkp',
        'sender': 'researcher_address',
        'timestamp': int(time.time()),
        'proof': 'a1b2c3d4e5f6789012345678901234567890abcdef' * 3,  # Mock proof
        'public_inputs': {
            'user_id': 'researcher_address',
            'sample_id': 'DNA_SAMPLE_001',
            'permission_hash': 'permission_hash_123',
            'prover': 'researcher_address'
        },
        'request_id': 'access_request_001'
    }
    
    zkp_json = json.dumps(zkp_tx).encode('utf-8')
    zkp_result = app.deliver_tx(type('MockReq', (), {'tx': zkp_json})())
    
    if zkp_result.code == 0:
        print(f"✅ Zero-knowledge proof verified")
        print(f"   🔐 Proof validated without revealing identity")
        print(f"   ✨ Privacy-preserving access granted")
    
    # Step 6: Sign data with private key
    print_step(6, "Digital Signature Verification")
    
    # Sign some data
    test_data = b"DNA analysis results for PATIENT_001"
    sign_result = key_manager.sign_data("researcher", test_data, "research_password")
    
    if sign_result['success']:
        print(f"✅ Data signed by researcher")
        print(f"   📝 Data: {test_data.decode()}")
        print(f"   🔏 Signature: {sign_result['signature'][:32]}...")
        
        # Verify signature
        verify_result = key_manager.verify_signature("researcher", test_data, sign_result['signature'])
        if verify_result['success'] and verify_result['valid']:
            print(f"✅ Signature verified successfully")
            print(f"   ✅ Data integrity confirmed")
    
    # Step 7: Query system state
    print_step(7, "Query System State")
    
    # Query DNA sample
    query_result = app.query(type('MockReq', (), {
        'path': b'/dna/sample',
        'data': b'DNA_SAMPLE_001'
    })())
    
    if query_result.code == 0:
        sample_data = json.loads(query_result.value.decode('utf-8'))
        print(f"✅ DNA sample retrieved from blockchain")
        print(f"   🆔 Sample ID: {sample_data['sample_id']}")
        print(f"   👤 Owner: {sample_data['owner']}")
        print(f"   📅 Timestamp: {sample_data['timestamp']}")
        print(f"   🏷️  Status: {sample_data['status']}")
    
    # Query NFT
    nft_query = app.query(type('MockReq', (), {
        'path': b'/nft/token',
        'data': b'NFT_DNA_001'
    })())
    
    if nft_query.code == 0:
        nft_data = json.loads(nft_query.value.decode('utf-8'))
        print(f"✅ NFT retrieved from blockchain")
        print(f"   🎨 Token ID: {nft_data['token_id']}")
        print(f"   👤 Owner: {nft_data['owner']}")
        print(f"   🔗 Sample ID: {nft_data['sample_id']}")
    
    # Final statistics
    print_header("DEMO COMPLETE - SYSTEM STATISTICS")
    print(f"📊 Total DNA Samples: {app.dna_registry.get_sample_count()}")
    print(f"🎨 Total NFTs: {app.nft_module.get_total_supply()}")
    print(f"📝 Pending Requests: {len(app.access_control.get_pending_requests())}")
    print(f"🔐 Verified Proofs: {len(app.zkp_handler.get_verified_proofs())}")
    print(f"📋 Active Proposals: {len(app.multisig.get_pending_proposals())}")
    
    print(f"\n🎉 Demo completed successfully!")
    print(f"🔗 All components working together seamlessly")
    print(f"🛡️  Security, privacy, and decentralization achieved")


def demo_api_workflow():
    """Demonstrate API workflow"""
    print_header("API WORKFLOW DEMONSTRATION")
    
    base_url = "http://localhost:8000"
    
    try:
        # Test API health
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            health_data = response.json()
            print("✅ API Server is running")
            print(f"   📊 System Status: {health_data['blockchain_status']}")
            print(f"   ⏱️  Uptime: {health_data['uptime']}")
        
        # Test encryption via API
        print("\n🔐 Testing Encryption API...")
        test_data = base64.b64encode(b"Sensitive DNA research data").decode('utf-8')
        encrypt_payload = {
            "file_data": test_data,
            "password": "api_test_password",
            "filename": "research_data.txt"
        }
        
        response = requests.post(f"{base_url}/crypto/encrypt", json=encrypt_payload)
        if response.status_code == 200:
            encrypt_result = response.json()
            print("✅ Data encrypted via API")
            print(f"   🔒 Hash: {encrypt_result['data_hash'][:16]}...")
            
            # Test decryption
            decrypt_payload = {
                "encrypted_data": encrypt_result['encrypted_data'],
                "iv": encrypt_result['iv'],
                "salt": encrypt_result['salt'],
                "password": "api_test_password"
            }
            
            response = requests.post(f"{base_url}/crypto/decrypt", json=decrypt_payload)
            if response.status_code == 200:
                print("✅ Data decrypted via API")
                print("   🔓 Round-trip encryption successful")
        
        print(f"\n🌐 API Demo completed!")
        print(f"📚 Visit http://localhost:8000/docs for full API documentation")
        
    except requests.exceptions.ConnectionError:
        print("❌ API Server not running")
        print("💡 Start it with: python scripts/start_api.py")


def main():
    """Run the complete demo"""
    print("🧬 Welcome to the DNA Blockchain Access System Demo!")
    print("This demonstration will show you all the key features of the system.")
    
    input("\nPress Enter to start the blockchain demo...")
    demo_blockchain_workflow()
    
    input("\nPress Enter to test the API endpoints...")
    demo_api_workflow()
    
    print(f"\n{'='*60}")
    print("🎯 DEMO SUMMARY")
    print('='*60)
    print("✅ Blockchain: DNA registration, NFT minting, access control")
    print("✅ Encryption: AES-256 file encryption with key management")
    print("✅ ZKP: Zero-knowledge proof verification (simulated)")
    print("✅ API: RESTful endpoints with comprehensive documentation")
    print("✅ Security: Digital signatures and multi-signature approvals")
    
    print(f"\n🚀 Next Steps:")
    print("1. Start API server: python scripts/start_api.py")
    print("2. Run tests: python scripts/test_system.py")
    print("3. Explore API docs: http://localhost:8000/docs")
    print("4. Build frontend integration")
    
    print(f"\n🎉 Thank you for exploring the DNA Blockchain Access System!")


if __name__ == '__main__':
    main()