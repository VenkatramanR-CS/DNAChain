"""
FastAPI Application for DNA Blockchain Access System
Main API server providing REST endpoints for the system
"""

import os
import json
import base64
import time
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models.schemas import *
from blockchain.abci_app import DNABlockchainApp
from encryption.aes_crypto import AESCrypto
from encryption.key_manager import KeyManager
from firebase.storage_handler import FirebaseStorageHandler
from firebase.firestore_handler import FirestoreHandler
from zkp.python.proof_generator import NoirProofGenerator
from zkp.python.proof_verifier import NoirProofVerifier

# Initialize FastAPI app
app = FastAPI(
    title="DNA Blockchain Access System API",
    description="Secure, decentralized DNA sample storage and access control",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
blockchain_app = DNABlockchainApp()
crypto = AESCrypto()
key_manager = KeyManager()
firebase_storage = FirebaseStorageHandler()
firestore_db = FirestoreHandler()
zkp_generator = NoirProofGenerator()
zkp_verifier = NoirProofVerifier()

# Global state for demo (in production, this would be persistent)
app_state = {
    'start_time': time.time(),
    'request_count': 0
}


def get_blockchain_app():
    """Dependency to get blockchain app instance"""
    return blockchain_app


def get_crypto():
    """Dependency to get crypto instance"""
    return crypto


def get_key_manager():
    """Dependency to get key manager instance"""
    return key_manager


def get_firebase_storage():
    """Dependency to get Firebase storage instance"""
    return firebase_storage


def get_firestore_db():
    """Dependency to get Firestore database instance"""
    return firestore_db


def get_zkp_generator():
    """Dependency to get ZKP generator instance"""
    return zkp_generator


def get_zkp_verifier():
    """Dependency to get ZKP verifier instance"""
    return zkp_verifier


@app.middleware("http")
async def request_counter(request, call_next):
    """Count requests for statistics"""
    app_state['request_count'] += 1
    response = await call_next(request)
    return response


@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint"""
    return {
        "message": "DNA Blockchain Access System API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health", response_model=SystemStatus)
async def health_check(blockchain: DNABlockchainApp = Depends(get_blockchain_app)):
    """Health check endpoint"""
    try:
        # Get system statistics
        uptime = time.time() - app_state['start_time']
        uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s"
        
        return SystemStatus(
            blockchain_status="running",
            total_samples=blockchain.dna_registry.get_sample_count(),
            total_nfts=blockchain.nft_module.get_total_supply(),
            pending_requests=len(blockchain.access_control.get_pending_requests()),
            verified_proofs=len(blockchain.zkp_handler.get_verified_proofs()),
            active_proposals=len(blockchain.multisig.get_pending_proposals()),
            uptime=uptime_str
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


# DNA Sample Endpoints
@app.post("/dna/upload", response_model=TransactionResponse)
async def upload_dna_sample(
    request: DNASampleUpload,
    blockchain: DNABlockchainApp = Depends(get_blockchain_app),
    crypto: AESCrypto = Depends(get_crypto)
):
    """Upload and register a DNA sample"""
    try:
        # Decode file data
        file_data = base64.b64decode(request.file_data)
        
        # Encrypt file data
        encryption_result = crypto.encrypt_data(file_data, request.password)
        if not encryption_result['success']:
            raise HTTPException(status_code=400, detail=encryption_result['error'])
        
        # Create transaction data
        tx_data = {
            'type': 'register_dna',
            'sender': request.owner,
            'timestamp': int(time.time()),
            'sample_id': request.sample_id,
            'cid': f"encrypted_{request.sample_id}",  # Would be IPFS CID in production
            'file_hash': encryption_result['data_hash'],
            'metadata': request.metadata
        }
        
        # Submit transaction
        tx_json = json.dumps(tx_data).encode('utf-8')
        result = blockchain.deliver_tx(type('MockReq', (), {'tx': tx_json})())
        
        if result.code == 0:
            return TransactionResponse(
                success=True,
                message=result.log,
                events=[],  # Would parse events from result
                data={
                    'sample_id': request.sample_id,
                    'file_hash': encryption_result['data_hash'],
                    'encrypted': True
                }
            )
        else:
            raise HTTPException(status_code=400, detail=result.log)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.get("/dna/sample/{sample_id}", response_model=DNASampleResponse)
async def get_dna_sample(
    sample_id: str,
    blockchain: DNABlockchainApp = Depends(get_blockchain_app)
):
    """Get DNA sample information"""
    try:
        query_result = blockchain.query(type('MockReq', (), {
            'path': b'/dna/sample',
            'data': sample_id.encode('utf-8')
        })())
        
        if query_result.code == 0:
            sample_data = json.loads(query_result.value.decode('utf-8'))
            return DNASampleResponse(**sample_data)
        else:
            raise HTTPException(status_code=404, detail="Sample not found")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")


# NFT Endpoints
@app.post("/nft/mint", response_model=TransactionResponse)
async def mint_nft(
    request: NFTMintRequest,
    blockchain: DNABlockchainApp = Depends(get_blockchain_app)
):
    """Mint an NFT for a DNA sample"""
    try:
        tx_data = {
            'type': 'mint_nft',
            'sender': request.owner,
            'timestamp': int(time.time()),
            'token_id': request.token_id,
            'sample_id': request.sample_id,
            'metadata_uri': request.metadata_uri
        }
        
        tx_json = json.dumps(tx_data).encode('utf-8')
        result = blockchain.deliver_tx(type('MockReq', (), {'tx': tx_json})())
        
        if result.code == 0:
            return TransactionResponse(
                success=True,
                message=result.log,
                data={'token_id': request.token_id}
            )
        else:
            raise HTTPException(status_code=400, detail=result.log)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Minting failed: {str(e)}")


@app.get("/nft/token/{token_id}", response_model=NFTResponse)
async def get_nft(
    token_id: str,
    blockchain: DNABlockchainApp = Depends(get_blockchain_app)
):
    """Get NFT information"""
    try:
        query_result = blockchain.query(type('MockReq', (), {
            'path': b'/nft/token',
            'data': token_id.encode('utf-8')
        })())
        
        if query_result.code == 0:
            nft_data = json.loads(query_result.value.decode('utf-8'))
            return NFTResponse(**nft_data)
        else:
            raise HTTPException(status_code=404, detail="NFT not found")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")


# Access Control Endpoints
@app.post("/access/request", response_model=TransactionResponse)
async def request_access(
    request: AccessRequest,
    blockchain: DNABlockchainApp = Depends(get_blockchain_app)
):
    """Request access to a DNA sample"""
    try:
        tx_data = {
            'type': 'request_access',
            'sender': request.requester,
            'timestamp': int(time.time()),
            'sample_id': request.sample_id,
            'purpose': request.purpose
        }
        
        tx_json = json.dumps(tx_data).encode('utf-8')
        result = blockchain.deliver_tx(type('MockReq', (), {'tx': tx_json})())
        
        if result.code == 0:
            return TransactionResponse(
                success=True,
                message=result.log
            )
        else:
            raise HTTPException(status_code=400, detail=result.log)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Access request failed: {str(e)}")


@app.get("/access/requests/pending")
async def get_pending_requests(
    blockchain: DNABlockchainApp = Depends(get_blockchain_app)
):
    """Get all pending access requests"""
    try:
        pending_requests = blockchain.access_control.get_pending_requests()
        return {"requests": pending_requests}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")


# ZKP Endpoints
@app.post("/zkp/verify", response_model=TransactionResponse)
async def verify_zkp(
    request: ZKProofRequest,
    blockchain: DNABlockchainApp = Depends(get_blockchain_app)
):
    """Verify a zero-knowledge proof"""
    try:
        tx_data = {
            'type': 'verify_zkp',
            'sender': request.public_inputs.get('prover', 'unknown'),
            'timestamp': int(time.time()),
            'proof': request.proof,
            'public_inputs': request.public_inputs,
            'request_id': request.request_id
        }
        
        tx_json = json.dumps(tx_data).encode('utf-8')
        result = blockchain.deliver_tx(type('MockReq', (), {'tx': tx_json})())
        
        if result.code == 0:
            return TransactionResponse(
                success=True,
                message=result.log
            )
        else:
            raise HTTPException(status_code=400, detail=result.log)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ZKP verification failed: {str(e)}")


# Encryption Endpoints
@app.post("/crypto/encrypt", response_model=EncryptionResponse)
async def encrypt_data(
    request: EncryptionRequest,
    crypto: AESCrypto = Depends(get_crypto)
):
    """Encrypt file data"""
    try:
        # Decode file data
        file_data = base64.b64decode(request.file_data)
        
        # Encrypt
        result = crypto.encrypt_data(file_data, request.password)
        
        if result['success']:
            return EncryptionResponse(
                success=True,
                encrypted_data=result['encrypted_data'],
                iv=result['iv'],
                salt=result['salt'],
                data_hash=result['data_hash']
            )
        else:
            return EncryptionResponse(
                success=False,
                error=result.get('error', 'Encryption failed')
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")


@app.post("/crypto/decrypt", response_model=DecryptionResponse)
async def decrypt_data(
    request: DecryptionRequest,
    crypto: AESCrypto = Depends(get_crypto)
):
    """Decrypt file data"""
    try:
        result = crypto.decrypt_data(
            request.encrypted_data,
            request.iv,
            request.salt,
            request.password
        )
        
        if result['success']:
            # Encode decrypted data as base64
            decrypted_b64 = base64.b64encode(result['decrypted_data']).decode('utf-8')
            
            return DecryptionResponse(
                success=True,
                decrypted_data=decrypted_b64,
                data_hash=result['data_hash']
            )
        else:
            return DecryptionResponse(
                success=False,
                error=result.get('error', 'Decryption failed')
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")


# Key Management Endpoints
@app.post("/keys/generate", response_model=KeyGenerationResponse)
async def generate_keypair(
    request: KeyGenerationRequest,
    key_manager: KeyManager = Depends(get_key_manager)
):
    """Generate RSA keypair for user"""
    try:
        result = key_manager.generate_user_keypair(request.user_id, request.password)
        
        if result['success']:
            return KeyGenerationResponse(
                success=True,
                user_id=result['user_id'],
                fingerprint=result['fingerprint'],
                message=result['message']
            )
        else:
            return KeyGenerationResponse(
                success=False,
                error=result.get('error', 'Key generation failed')
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")


@app.post("/keys/sign", response_model=SignatureResponse)
async def sign_data(
    request: SignatureRequest,
    key_manager: KeyManager = Depends(get_key_manager)
):
    """Sign data with user's private key"""
    try:
        # Decode data
        data = base64.b64decode(request.data)
        
        result = key_manager.sign_data(request.user_id, data, request.password)
        
        if result['success']:
            return SignatureResponse(
                success=True,
                signature=result['signature'],
                user_id=result['user_id'],
                data_hash=result['data_hash']
            )
        else:
            return SignatureResponse(
                success=False,
                error=result.get('error', 'Signing failed')
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signing failed: {str(e)}")


@app.post("/keys/verify", response_model=VerificationResponse)
async def verify_signature(
    request: VerificationRequest,
    key_manager: KeyManager = Depends(get_key_manager)
):
    """Verify signature with user's public key"""
    try:
        # Decode data
        data = base64.b64decode(request.data)
        
        result = key_manager.verify_signature(request.user_id, data, request.signature)
        
        if result['success']:
            return VerificationResponse(
                success=True,
                valid=result['valid'],
                user_id=result['user_id'],
                data_hash=result['data_hash']
            )
        else:
            return VerificationResponse(
                success=False,
                error=result.get('error', 'Verification failed')
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler"""
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Firebase Storage Endpoints
@app.post("/storage/upload", response_model=Dict[str, Any])
async def upload_to_firebase(
    file_data: str,
    file_path: str,
    metadata: Dict[str, Any] = None,
    storage: FirebaseStorageHandler = Depends(get_firebase_storage)
):
    """Upload file to Firebase Storage"""
    try:
        # Decode base64 file data
        file_bytes = base64.b64decode(file_data)
        
        result = storage.upload_encrypted_file(file_bytes, file_path, metadata)
        
        if result['success']:
            return {
                'success': True,
                'file_path': result['file_path'],
                'download_url': result.get('download_url'),
                'file_hash': result['file_hash'],
                'file_size': result['file_size']
            }
        else:
            raise HTTPException(status_code=400, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.get("/storage/download/{file_path:path}")
async def download_from_firebase(
    file_path: str,
    storage: FirebaseStorageHandler = Depends(get_firebase_storage)
):
    """Download file from Firebase Storage"""
    try:
        result = storage.download_encrypted_file(file_path)
        
        if result['success']:
            # Encode file data as base64
            file_data_b64 = base64.b64encode(result['file_data']).decode('utf-8')
            
            return {
                'success': True,
                'file_data': file_data_b64,
                'file_hash': result['file_hash'],
                'file_size': result['file_size'],
                'metadata': result.get('metadata', {})
            }
        else:
            raise HTTPException(status_code=404, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")


@app.get("/storage/list")
async def list_firebase_files(
    prefix: str = "",
    limit: int = 100,
    storage: FirebaseStorageHandler = Depends(get_firebase_storage)
):
    """List files in Firebase Storage"""
    try:
        result = storage.list_files(prefix, limit)
        
        if result['success']:
            return {
                'success': True,
                'files': result['files'],
                'count': result['count']
            }
        else:
            raise HTTPException(status_code=500, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"List failed: {str(e)}")


# Firestore Endpoints
@app.post("/users/create", response_model=Dict[str, Any])
async def create_user_profile(
    user_id: str,
    profile_data: Dict[str, Any],
    db: FirestoreHandler = Depends(get_firestore_db)
):
    """Create user profile in Firestore"""
    try:
        result = db.create_user_profile(user_id, profile_data)
        
        if result['success']:
            return {
                'success': True,
                'user_id': result['user_id'],
                'message': result['message']
            }
        else:
            raise HTTPException(status_code=400, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"User creation failed: {str(e)}")


@app.get("/users/{user_id}")
async def get_user_profile(
    user_id: str,
    db: FirestoreHandler = Depends(get_firestore_db)
):
    """Get user profile from Firestore"""
    try:
        result = db.get_user_profile(user_id)
        
        if result['success']:
            return {
                'success': True,
                'user_data': result['user_data']
            }
        else:
            raise HTTPException(status_code=404, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"User retrieval failed: {str(e)}")


@app.post("/metadata/store")
async def store_sample_metadata(
    sample_id: str,
    metadata: Dict[str, Any],
    db: FirestoreHandler = Depends(get_firestore_db)
):
    """Store DNA sample metadata in Firestore"""
    try:
        result = db.store_sample_metadata(sample_id, metadata)
        
        if result['success']:
            return {
                'success': True,
                'sample_id': result['sample_id'],
                'message': result['message']
            }
        else:
            raise HTTPException(status_code=400, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Metadata storage failed: {str(e)}")


@app.get("/metadata/{sample_id}")
async def get_sample_metadata(
    sample_id: str,
    db: FirestoreHandler = Depends(get_firestore_db)
):
    """Get DNA sample metadata from Firestore"""
    try:
        result = db.get_sample_metadata(sample_id)
        
        if result['success']:
            return {
                'success': True,
                'metadata': result['metadata']
            }
        else:
            raise HTTPException(status_code=404, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Metadata retrieval failed: {str(e)}")


@app.get("/analytics/stats")
async def get_system_analytics(
    db: FirestoreHandler = Depends(get_firestore_db)
):
    """Get system analytics and statistics"""
    try:
        result = db.get_system_stats()
        
        if result['success']:
            return {
                'success': True,
                'stats': result['stats'],
                'generated_at': result['generated_at']
            }
        else:
            raise HTTPException(status_code=500, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analytics retrieval failed: {str(e)}")


# Enhanced ZKP Endpoints
@app.post("/zkp/generate", response_model=Dict[str, Any])
async def generate_zkp(
    circuit_type: str,
    user_secret: str,
    sample_id: str = None,
    personal_data: Dict[str, Any] = None,
    challenge: str = None,
    generator: NoirProofGenerator = Depends(get_zkp_generator)
):
    """Generate zero-knowledge proof"""
    try:
        if circuit_type == 'access_permission':
            if not sample_id:
                raise HTTPException(status_code=400, detail="sample_id required for access permission proof")
            
            permission_data = {
                'timestamp': int(time.time()),
                'sample_id': sample_id
            }
            
            result = generator.generate_access_permission_proof(user_secret, sample_id, permission_data)
            
        elif circuit_type == 'identity_verification':
            if not personal_data or not challenge:
                raise HTTPException(status_code=400, detail="personal_data and challenge required for identity proof")
            
            result = generator.generate_identity_proof(user_secret, personal_data, challenge)
            
        else:
            raise HTTPException(status_code=400, detail=f"Unknown circuit type: {circuit_type}")
        
        if result['success']:
            return {
                'success': True,
                'proof': result['proof'],
                'public_inputs': result['public_inputs'],
                'circuit_type': result['circuit_type']
            }
        else:
            raise HTTPException(status_code=400, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proof generation failed: {str(e)}")


@app.post("/zkp/verify-advanced", response_model=Dict[str, Any])
async def verify_zkp_advanced(
    proof: str,
    public_inputs: Dict[str, Any],
    circuit_type: str,
    sample_id: str = None,
    challenge: str = None,
    verifier: NoirProofVerifier = Depends(get_zkp_verifier)
):
    """Advanced zero-knowledge proof verification"""
    try:
        if circuit_type == 'access_permission':
            if not sample_id:
                raise HTTPException(status_code=400, detail="sample_id required for access permission verification")
            
            result = verifier.verify_access_permission_proof(proof, public_inputs, sample_id)
            
        elif circuit_type == 'identity_verification':
            if not challenge:
                raise HTTPException(status_code=400, detail="challenge required for identity verification")
            
            result = verifier.verify_identity_proof(proof, public_inputs, challenge)
            
        else:
            raise HTTPException(status_code=400, detail=f"Unknown circuit type: {circuit_type}")
        
        if result['success']:
            return {
                'success': True,
                'valid': result['valid'],
                'circuit_type': result['circuit_type'],
                'verification_details': result.get('verification_details', {})
            }
        else:
            raise HTTPException(status_code=400, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proof verification failed: {str(e)}")


@app.post("/zkp/batch-verify")
async def batch_verify_proofs(
    proofs: List[Dict[str, Any]],
    verifier: NoirProofVerifier = Depends(get_zkp_verifier)
):
    """Batch verify multiple zero-knowledge proofs"""
    try:
        result = verifier.batch_verify_proofs(proofs)
        
        if result['success']:
            return {
                'success': True,
                'results': result['results'],
                'statistics': result['statistics']
            }
        else:
            raise HTTPException(status_code=400, detail=result['error'])
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch verification failed: {str(e)}")


# Enhanced DNA Sample Management
@app.post("/dna/upload-advanced", response_model=TransactionResponse)
async def upload_dna_sample_advanced(
    request: DNASampleUpload,
    blockchain: DNABlockchainApp = Depends(get_blockchain_app),
    crypto: AESCrypto = Depends(get_crypto),
    storage: FirebaseStorageHandler = Depends(get_firebase_storage),
    db: FirestoreHandler = Depends(get_firestore_db)
):
    """Advanced DNA sample upload with Firebase integration"""
    try:
        # Decode file data
        file_data = base64.b64decode(request.file_data)
        
        # Encrypt file data
        encryption_result = crypto.encrypt_data(file_data, request.password)
        if not encryption_result['success']:
            raise HTTPException(status_code=400, detail=encryption_result['error'])
        
        # Upload to Firebase Storage
        file_path = f"samples/{request.sample_id}.encrypted"
        storage_result = storage.upload_encrypted_file(
            encryption_result['encrypted_data'].encode(),
            file_path,
            {
                'sample_id': request.sample_id,
                'owner': request.owner,
                'encrypted': True,
                'algorithm': 'AES-256-CBC'
            }
        )
        
        if not storage_result['success']:
            raise HTTPException(status_code=500, detail=f"Storage upload failed: {storage_result['error']}")
        
        # Store metadata in Firestore
        metadata_result = db.store_sample_metadata(request.sample_id, {
            'owner': request.owner,
            'file_path': file_path,
            'file_hash': encryption_result['data_hash'],
            'metadata': request.metadata,
            'encrypted': True,
            'storage_url': storage_result.get('download_url')
        })
        
        # Register on blockchain
        tx_data = {
            'type': 'register_dna',
            'sender': request.owner,
            'timestamp': int(time.time()),
            'sample_id': request.sample_id,
            'cid': storage_result.get('file_path', f"firebase_{request.sample_id}"),
            'file_hash': encryption_result['data_hash'],
            'metadata': request.metadata
        }
        
        tx_json = json.dumps(tx_data).encode('utf-8')
        result = blockchain.deliver_tx(type('MockReq', (), {'tx': tx_json})())
        
        if result.code == 0:
            # Log access event
            db.log_access_event({
                'event_type': 'sample_uploaded',
                'sample_id': request.sample_id,
                'user_id': request.owner,
                'file_size': len(file_data),
                'encrypted': True
            })
            
            return TransactionResponse(
                success=True,
                message=result.log,
                data={
                    'sample_id': request.sample_id,
                    'file_hash': encryption_result['data_hash'],
                    'storage_path': file_path,
                    'encrypted': True,
                    'firebase_url': storage_result.get('download_url')
                }
            )
        else:
            raise HTTPException(status_code=400, detail=result.log)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Advanced upload failed: {str(e)}")


# System Management Endpoints
@app.get("/system/full-status")
async def get_full_system_status(
    blockchain: DNABlockchainApp = Depends(get_blockchain_app),
    storage: FirebaseStorageHandler = Depends(get_firebase_storage),
    db: FirestoreHandler = Depends(get_firestore_db)
):
    """Get comprehensive system status"""
    try:
        # Get blockchain stats
        uptime = time.time() - app_state['start_time']
        uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s"
        
        # Get storage stats
        storage_files = storage.list_files("samples/", 100)
        
        # Get database stats
        db_stats = db.get_system_stats()
        
        return {
            'blockchain': {
                'status': 'running',
                'total_samples': blockchain.dna_registry.get_sample_count(),
                'total_nfts': blockchain.nft_module.get_total_supply(),
                'pending_requests': len(blockchain.access_control.get_pending_requests()),
                'verified_proofs': len(blockchain.zkp_handler.get_verified_proofs()),
                'active_proposals': len(blockchain.multisig.get_pending_proposals())
            },
            'storage': {
                'status': 'connected' if storage.initialized else 'simulated',
                'total_files': storage_files.get('count', 0) if storage_files.get('success') else 0
            },
            'database': {
                'status': 'connected' if db.initialized else 'simulated',
                'stats': db_stats.get('stats', {}) if db_stats.get('success') else {}
            },
            'api': {
                'status': 'running',
                'uptime': uptime_str,
                'total_requests': app_state['request_count']
            },
            'generated_at': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")


# Add missing imports
from datetime import datetime
from typing import List