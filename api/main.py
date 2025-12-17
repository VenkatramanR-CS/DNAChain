"""
Complete FastAPI Application for DNA Blockchain Access System
Main API server with Firebase Authentication and all features
"""

import os
import json
import base64
import time
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .models.schemas import *
from .auth import firebase_auth, get_current_user
from blockchain.abci_app import DNABlockchainApp
from encryption.aes_crypto import AESCrypto
from encryption.key_manager import KeyManager
from dna_firebase.storage_handler import FirebaseStorageHandler
from dna_firebase.firestore_handler import FirestoreHandler
from zkp.python.proof_generator import NoirProofGenerator
from zkp.python.proof_verifier import NoirProofVerifier

# Helper functions for Firestore compatibility
def get_access_request_data(firestore_db, request_id: str) -> Dict[str, Any]:
    """Helper to get access request data using available methods"""
    result = firestore_db.get_sample_metadata(f"access_request_{request_id}")
    return result.get('metadata', {}) if result.get('success') else {}

def store_zkp_proof_data(firestore_db, proof_id: str, data: Dict[str, Any]) -> bool:
    """Helper to store ZKP proof data using available methods"""
    result = firestore_db.store_sample_metadata(f"zkp_proof_{proof_id}", {**data, 'type': 'zkp_proof'})
    return result.get('success', False)

def get_zkp_proof_data(firestore_db, proof_id: str) -> Dict[str, Any]:
    """Helper to get ZKP proof data using available methods"""
    result = firestore_db.get_sample_metadata(f"zkp_proof_{proof_id}")
    return result.get('metadata', {}) if result.get('success') else {}

def update_access_request_status_data(firestore_db, request_id: str, status: str) -> bool:
    """Helper to update access request status using available methods"""
    current_data = get_access_request_data(firestore_db, request_id)
    current_data.update({'status': status, 'updated_at': time.time()})
    result = firestore_db.store_sample_metadata(f"access_request_{request_id}", current_data)
    return result.get('success', False)

# Initialize FastAPI app
app = FastAPI(
    title="DNA Blockchain Access System API",
    description="Secure, decentralized DNA sample storage and access control with Firebase Authentication",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:3000", "http://127.0.0.1:8080"],
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

# Security
security = HTTPBearer()

# System startup time
startup_time = time.time()


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.post("/auth/register", response_model=AuthResponse, tags=["Authentication"])
async def register_user(registration: UserRegistration):
    """Register a new user with Firebase Authentication"""
    try:
        result = await firebase_auth.register_user(registration)
        
        if result.success and result.user:
            # Generate RSA keypair for the user
            key_result = key_manager.generate_user_keypair(
                result.user.uid, 
                registration.password
            )
            
            if not key_result['success']:
                print(f"Warning: Failed to generate keypair for user {result.user.uid}")
        
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )


@app.post("/auth/login", response_model=AuthResponse, tags=["Authentication"])
async def login_user(login: UserLogin):
    """Login user with Firebase Authentication"""
    try:
        result = await firebase_auth.login_user(login)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )


@app.get("/auth/profile", response_model=UserProfile, tags=["Authentication"])
async def get_user_profile(current_user: UserProfile = Depends(get_current_user)):
    """Get current user profile"""
    return current_user


@app.put("/auth/profile", tags=["Authentication"])
async def update_user_profile(
    updates: Dict[str, Any],
    current_user: UserProfile = Depends(get_current_user)
):
    """Update user profile"""
    try:
        # Filter allowed updates
        allowed_fields = ['display_name', 'wallet_address']
        filtered_updates = {k: v for k, v in updates.items() if k in allowed_fields}
        
        success = await firebase_auth.update_user_profile(current_user.uid, filtered_updates)
        
        if success:
            return {"success": True, "message": "Profile updated successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update profile"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Profile update failed: {str(e)}"
        )


# ============================================================================
# DNA SAMPLE MANAGEMENT ENDPOINTS
# ============================================================================

@app.post("/dna/upload", response_model=TransactionResponse, tags=["DNA Samples"])
async def upload_dna_sample(
    upload_data: DNASampleUpload,
    current_user: UserProfile = Depends(get_current_user)
):
    """Upload and register DNA sample with encryption"""
    try:
        # Verify ownership
        if upload_data.owner != current_user.wallet_address and upload_data.owner != current_user.uid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only upload samples for yourself"
            )
        
        # Encrypt the file data
        file_data = base64.b64decode(upload_data.file_data)
        encryption_result = crypto.encrypt_data(file_data, upload_data.password)
        
        if not encryption_result['success']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Encryption failed: {encryption_result['error']}"
            )
        
        # Store in Firebase Storage
        storage_result = firebase_storage.upload_encrypted_file(
            base64.b64decode(encryption_result['encrypted_data']),
            f"dna_samples/{upload_data.sample_id}.enc"
        )
        
        # Prepare blockchain transaction
        tx_data = {
            'sample_id': upload_data.sample_id,
            'owner': current_user.uid,
            'file_hash': encryption_result['data_hash'],
            'cid': storage_result.get('file_path', ''),
            'metadata': {
                **upload_data.metadata,
                'encrypted': True,
                'iv': encryption_result['iv'],
                'salt': encryption_result['salt'],
                'uploader_uid': current_user.uid,
                'upload_timestamp': int(time.time())
            }
        }
        
        # Submit to blockchain
        result = blockchain_app.register_dna_sample(tx_data)
        
        # Store metadata in Firestore
        if result['success']:
            firestore_db.store_sample_metadata(upload_data.sample_id, {
                'sample_id': upload_data.sample_id,
                'owner_uid': current_user.uid,
                'owner_email': current_user.email,
                'file_hash': encryption_result['data_hash'],
                'storage_path': storage_result.get('file_path', ''),
                'metadata': tx_data['metadata'],
                'created_at': time.time(),
                'status': 'active'
            })
        
        return TransactionResponse(
            success=result['success'],
            message=result.get('message', 'DNA sample uploaded successfully'),
            tx_hash=result.get('tx_hash'),
            data={
                'sample_id': upload_data.sample_id,
                'file_hash': encryption_result['data_hash'],
                'storage_path': storage_result.get('file_path', '')
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload failed: {str(e)}"
        )


@app.get("/dna/samples", tags=["DNA Samples"])
async def list_user_samples(current_user: UserProfile = Depends(get_current_user)):
    """List DNA samples owned by the current user"""
    try:
        # Get samples from Firestore
        samples = firestore_db.query_samples_by_owner(current_user.uid)
        
        # Also get from blockchain for verification
        blockchain_samples = blockchain_app.get_user_samples(current_user.uid)
        
        return {
            "success": True,
            "samples": samples,
            "total_count": len(samples)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve samples: {str(e)}"
        )


@app.get("/dna/sample/{sample_id}", tags=["DNA Samples"])
async def get_sample_details(
    sample_id: str,
    current_user: UserProfile = Depends(get_current_user)
):
    """Get detailed information about a DNA sample"""
    try:
        # Get sample from blockchain
        sample_data = blockchain_app.get_sample(sample_id)
        
        if not sample_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Sample not found"
            )
        
        # Check access permissions
        if sample_data['owner'] != current_user.uid:
            # Check if user has access permission
            has_access = blockchain_app.check_access_permission(current_user.uid, sample_id)
            if not has_access:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this sample"
                )
        
        # Get additional metadata from Firestore
        metadata = firestore_db.get_sample_metadata(sample_id)
        
        return {
            "success": True,
            "sample": {
                **sample_data,
                "firestore_metadata": metadata
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve sample: {str(e)}"
        )


@app.post("/dna/download/{sample_id}", tags=["DNA Samples"])
async def download_sample(
    sample_id: str,
    password: str,
    current_user: UserProfile = Depends(get_current_user)
):
    """Download and decrypt a DNA sample"""
    try:
        # Get sample info
        sample_data = blockchain_app.get_sample(sample_id)
        
        if not sample_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Sample not found"
            )
        
        # Check access permissions
        if sample_data['owner'] != current_user.uid:
            has_access = blockchain_app.check_access_permission(current_user.uid, sample_id)
            if not has_access:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this sample"
                )
        
        # Download from Firebase Storage
        storage_path = sample_data['metadata'].get('storage_path', f"dna_samples/{sample_id}.enc")
        download_result = firebase_storage.download_encrypted_file(storage_path)
        encrypted_data = download_result.get('file_data') if download_result.get('success') else None
        
        if not encrypted_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Sample file not found in storage"
            )
        
        # Decrypt the file
        decryption_result = crypto.decrypt_data(
            encrypted_data,
            sample_data['metadata']['iv'],
            sample_data['metadata']['salt'],
            password
        )
        
        if not decryption_result['success']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Decryption failed - incorrect password or corrupted data"
            )
        
        return {
            "success": True,
            "file_data": base64.b64encode(decryption_result['decrypted_data']).decode('utf-8'),
            "file_hash": decryption_result['data_hash'],
            "sample_id": sample_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Download failed: {str(e)}"
        )


# ============================================================================
# NFT MANAGEMENT ENDPOINTS
# ============================================================================

@app.post("/nft/mint", response_model=TransactionResponse, tags=["NFT Management"])
async def mint_nft(
    mint_data: NFTMintRequest,
    current_user: UserProfile = Depends(get_current_user)
):
    """Mint an NFT for a DNA sample"""
    try:
        # Verify sample ownership
        sample_data = blockchain_app.get_sample(mint_data.sample_id)
        
        if not sample_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="DNA sample not found"
            )
        
        if sample_data['owner'] != current_user.uid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only mint NFTs for your own samples"
            )
        
        # Prepare NFT data
        nft_data = {
            'token_id': mint_data.token_id,
            'owner': current_user.uid,
            'sample_id': mint_data.sample_id,
            'metadata_uri': mint_data.metadata_uri,
            'minter': current_user.uid,
            'mint_timestamp': int(time.time())
        }
        
        # Mint NFT on blockchain
        result = blockchain_app.mint_nft(nft_data)
        
        # Store NFT metadata in Firestore
        if result['success']:
            firestore_db.store_sample_metadata(f"nft_{mint_data.token_id}", {
                'token_id': mint_data.token_id,
                'owner_uid': current_user.uid,
                'sample_id': mint_data.sample_id,
                'metadata_uri': mint_data.metadata_uri,
                'minter_uid': current_user.uid,
                'created_at': time.time(),
                'status': 'active',
                'type': 'nft_metadata'
            })
        
        return TransactionResponse(
            success=result['success'],
            message=result.get('message', 'NFT minted successfully'),
            tx_hash=result.get('tx_hash'),
            data=nft_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"NFT minting failed: {str(e)}"
        )


@app.get("/nft/tokens", tags=["NFT Management"])
async def list_user_nfts(current_user: UserProfile = Depends(get_current_user)):
    """List NFTs owned by the current user"""
    try:
        # Get NFTs from blockchain
        nfts = blockchain_app.get_user_nfts(current_user.uid)
        
        # Get additional metadata from Firestore
        for nft in nfts:
            metadata_result = firestore_db.get_sample_metadata(f"nft_{nft['token_id']}")
            metadata = metadata_result.get('metadata') if metadata_result.get('success') else None
            if metadata:
                nft['firestore_metadata'] = metadata
        
        return {
            "success": True,
            "nfts": nfts,
            "total_count": len(nfts)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve NFTs: {str(e)}"
        )


@app.post("/nft/transfer", tags=["NFT Management"])
async def transfer_nft(
    transfer_data: NFTTransfer,
    current_user: UserProfile = Depends(get_current_user)
):
    """Transfer NFT to another user"""
    try:
        # Verify ownership
        nft_data = blockchain_app.get_nft(transfer_data.token_id)
        
        if not nft_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="NFT not found"
            )
        
        if nft_data['owner'] != current_user.uid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only transfer your own NFTs"
            )
        
        # Verify password by attempting to sign with user's private key
        test_signature = key_manager.sign_data(
            current_user.uid,
            f"transfer_{transfer_data.token_id}_{transfer_data.to_uid}".encode('utf-8'),
            transfer_data.password
        )
        
        if not test_signature['success']:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )
        
        # Get recipient user info
        recipient = await firebase_auth.get_user_profile(transfer_data.to_uid)
        if not recipient:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipient user not found"
            )
        
        # Transfer NFT on blockchain
        result = blockchain_app.transfer_nft(
            transfer_data.token_id,
            current_user.uid,
            transfer_data.to_uid
        )
        
        # Update Firestore metadata
        if result['success']:
            # Update NFT owner in Firestore (using generic update)
            firestore_db.store_sample_metadata(f"nft_{transfer_data.token_id}", {
                'owner_uid': transfer_data.to_uid,
                'updated_at': time.time(),
                'transfer_from': current_user.uid
            })
        
        return TransactionResponse(
            success=result['success'],
            message=result.get('message', 'NFT transferred successfully'),
            tx_hash=result.get('tx_hash'),
            data={
                'token_id': transfer_data.token_id,
                'from_uid': current_user.uid,
                'to_uid': transfer_data.to_uid,
                'recipient_email': recipient.email
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"NFT transfer failed: {str(e)}"
        )


# ============================================================================
# ACCESS CONTROL ENDPOINTS
# ============================================================================

@app.post("/access/request", response_model=TransactionResponse, tags=["Access Control"])
async def request_sample_access(
    access_request: AccessRequest,
    current_user: UserProfile = Depends(get_current_user)
):
    """Request access to a DNA sample"""
    try:
        # Verify sample exists
        sample_data = blockchain_app.get_sample(access_request.sample_id)
        
        if not sample_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="DNA sample not found"
            )
        
        # Can't request access to your own sample
        if sample_data['owner'] == current_user.uid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You already own this sample"
            )
        
        # Prepare access request data
        request_data = {
            'requester': current_user.uid,
            'sample_id': access_request.sample_id,
            'purpose': access_request.purpose,
            'expiry_hours': access_request.expiry_hours,
            'requester_email': current_user.email,
            'requester_name': current_user.display_name,
            'request_timestamp': int(time.time())
        }
        
        # Submit to blockchain
        result = blockchain_app.request_access(request_data)
        
        # Store in Firestore for notifications
        if result['success']:
            # Store access request in Firestore (using generic metadata storage)
            firestore_db.store_sample_metadata(f"access_request_{result['request_id']}", {
                **request_data,
                'request_id': result['request_id'],
                'status': 'pending',
                'created_at': time.time(),
                'type': 'access_request'
            })
        
        return TransactionResponse(
            success=result['success'],
            message=result.get('message', 'Access request submitted successfully'),
            tx_hash=result.get('tx_hash'),
            data={
                'request_id': result.get('request_id'),
                'sample_id': access_request.sample_id,
                'status': 'pending'
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Access request failed: {str(e)}"
        )


@app.get("/access/requests/pending", tags=["Access Control"])
async def get_pending_requests(current_user: UserProfile = Depends(get_current_user)):
    """Get pending access requests for samples owned by current user"""
    try:
        # Get requests from blockchain
        requests = blockchain_app.get_pending_requests_for_owner(current_user.uid)
        
        # Enrich with Firestore data
        for request in requests:
            firestore_data = get_access_request_data(firestore_db, request['request_id'])
            if firestore_data:
                request.update(firestore_data)
        
        return {
            "success": True,
            "requests": requests,
            "total_count": len(requests)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve pending requests: {str(e)}"
        )


@app.get("/access/requests/my", tags=["Access Control"])
async def get_my_requests(current_user: UserProfile = Depends(get_current_user)):
    """Get access requests made by current user"""
    try:
        # Get requests from blockchain
        requests = blockchain_app.get_user_requests(current_user.uid)
        
        # Enrich with Firestore data
        for request in requests:
            firestore_data = get_access_request_data(firestore_db, request['request_id'])
            if firestore_data:
                request.update(firestore_data)
        
        return {
            "success": True,
            "requests": requests,
            "total_count": len(requests)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve user requests: {str(e)}"
        )


@app.post("/access/approve", tags=["Access Control"])
async def approve_access_request(
    approval: AccessApproval,
    current_user: UserProfile = Depends(get_current_user)
):
    """Approve or deny an access request"""
    try:
        # Get request details
        request_data = blockchain_app.get_access_request(approval.request_id)
        
        if not request_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Access request not found"
            )
        
        # Verify user can approve this request (owns the sample)
        sample_data = blockchain_app.get_sample(request_data['sample_id'])
        if sample_data['owner'] != current_user.uid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only approve requests for your own samples"
            )
        
        # Process approval/denial
        if approval.action == "approve":
            result = blockchain_app.approve_access_request(
                approval.request_id,
                current_user.uid,
                approval.reason
            )
        elif approval.action == "deny":
            result = blockchain_app.deny_access_request(
                approval.request_id,
                current_user.uid,
                approval.reason
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Action must be 'approve' or 'deny'"
            )
        
        # Update Firestore
        if result['success']:
            update_access_request_status_data(
                firestore_db,
                approval.request_id,
                approval.action + "d"
            )
        
        return TransactionResponse(
            success=result['success'],
            message=result.get('message', f'Request {approval.action}d successfully'),
            tx_hash=result.get('tx_hash'),
            data={
                'request_id': approval.request_id,
                'action': approval.action,
                'approver': current_user.uid
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Approval failed: {str(e)}"
        )


# ============================================================================
# ZERO-KNOWLEDGE PROOF ENDPOINTS
# ============================================================================

@app.post("/zkp/generate", tags=["Zero-Knowledge Proofs"])
async def generate_zkp(
    circuit_type: str,
    sample_id: str,
    user_secret: str,
    current_user: UserProfile = Depends(get_current_user)
):
    """Generate a zero-knowledge proof"""
    try:
        # Verify user has access to the sample
        has_access = blockchain_app.check_access_permission(current_user.uid, sample_id)
        
        if not has_access:
            # Check if user owns the sample
            sample_data = blockchain_app.get_sample(sample_id)
            if not sample_data or sample_data['owner'] != current_user.uid:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this sample"
                )
        
        # Generate proof
        proof_data = {
            'prover': current_user.uid,
            'sample_id': sample_id,
            'circuit_type': circuit_type,
            'user_secret': user_secret,
            'timestamp': int(time.time())
        }
        
        # Extract and validate permission data
        permission_data = proof_data.get('permission_data', {})
        if not isinstance(permission_data, dict):
            permission_data = {}
        
        result = zkp_generator.generate_access_permission_proof(
            str(proof_data.get('user_secret', '')),
            str(proof_data.get('sample_id', '')),
            permission_data
        )
        
        if result['success']:
            # Store proof in blockchain
            blockchain_result = blockchain_app.store_zkp(
                result['proof_id'],
                current_user.uid,
                circuit_type,
                result['proof'],
                result['public_inputs']
            )
            
            # Store in Firestore
            store_zkp_proof_data(firestore_db, result['proof_id'], {
                'proof_id': result['proof_id'],
                'prover_uid': current_user.uid,
                'sample_id': sample_id,
                'circuit_type': circuit_type,
                'verified': result['verified'],
                'created_at': time.time()
            })
        
        return {
            "success": result['success'],
            "proof_id": result.get('proof_id'),
            "verified": result.get('verified', False),
            "message": result.get('message', 'Proof generated successfully')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Proof generation failed: {str(e)}"
        )


@app.post("/zkp/verify", response_model=TransactionResponse, tags=["Zero-Knowledge Proofs"])
async def verify_zkp(
    zkp_request: ZKProofRequest,
    current_user: UserProfile = Depends(get_current_user)
):
    """Verify a zero-knowledge proof"""
    try:
        # Verify the proof
        result = zkp_verifier.verify_access_permission_proof(
            zkp_request.proof,
            zkp_request.public_inputs,
            zkp_request.circuit_type
        )
        
        # Store verification result in blockchain
        if result['success']:
            blockchain_result = blockchain_app.verify_zkp(
                zkp_request.request_id,
                current_user.uid,
                result['verified'],
                zkp_request.circuit_type
            )
        
        return TransactionResponse(
            success=result['success'],
            message=result.get('message', 'Proof verification completed'),
            data={
                'verified': result.get('verified', False),
                'circuit_type': zkp_request.circuit_type,
                'verifier': current_user.uid
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Proof verification failed: {str(e)}"
        )


@app.get("/zkp/proofs", tags=["Zero-Knowledge Proofs"])
async def list_user_proofs(current_user: UserProfile = Depends(get_current_user)):
    """List zero-knowledge proofs generated by current user"""
    try:
        # Get proofs from blockchain
        proofs = blockchain_app.get_user_proofs(current_user.uid)
        
        # Enrich with Firestore data
        for proof in proofs:
            firestore_data = get_zkp_proof_data(firestore_db, proof['proof_id'])
            if firestore_data:
                proof.update(firestore_data)
        
        return {
            "success": True,
            "proofs": proofs,
            "total_count": len(proofs)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve proofs: {str(e)}"
        )


# ============================================================================
# SYSTEM MANAGEMENT ENDPOINTS
# ============================================================================

@app.get("/health", tags=["System"])
async def health_check():
    """Basic health check endpoint"""
    try:
        # Test blockchain
        blockchain_status = "healthy" if blockchain_app.is_healthy() else "unhealthy"
        
        # Test Firebase
        firebase_status = "healthy" if firebase_auth.initialized else "simulation"
        
        # Get system stats
        stats = blockchain_app.get_system_stats()
        
        uptime_seconds = int(time.time() - startup_time)
        uptime_hours = uptime_seconds // 3600
        uptime_minutes = (uptime_seconds % 3600) // 60
        
        return {
            "status": "healthy",
            "timestamp": int(time.time()),
            "uptime": f"{uptime_hours}h {uptime_minutes}m",
            "blockchain_status": blockchain_status,
            "firebase_status": firebase_status,
            "total_samples": stats.get('total_samples', 0),
            "total_nfts": stats.get('total_nfts', 0),
            "pending_requests": stats.get('pending_requests', 0),
            "verified_proofs": stats.get('verified_proofs', 0),
            "version": "2.0.0"
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": int(time.time())
        }


@app.get("/system/status", response_model=SystemStatus, tags=["System"])
async def get_system_status(current_user: UserProfile = Depends(get_current_user)):
    """Get comprehensive system status (requires authentication)"""
    try:
        stats = blockchain_app.get_system_stats()
        
        uptime_seconds = int(time.time() - startup_time)
        uptime_hours = uptime_seconds // 3600
        uptime_minutes = (uptime_seconds % 3600) // 60
        
        return SystemStatus(
            blockchain_status="healthy" if blockchain_app.is_healthy() else "unhealthy",
            total_samples=stats.get('total_samples', 0),
            total_nfts=stats.get('total_nfts', 0),
            pending_requests=stats.get('pending_requests', 0),
            verified_proofs=stats.get('verified_proofs', 0),
            active_proposals=stats.get('active_proposals', 0),
            uptime=f"{uptime_hours}h {uptime_minutes}m"
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get system status: {str(e)}"
        )


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": int(time.time())
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "timestamp": int(time.time())
        }
    )


# ============================================================================
# STARTUP EVENT
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize system on startup"""
    print("🧬 DNA Blockchain Access System API v2.0.0")
    print("=" * 50)
    print(f"🔥 Firebase Auth: {'✅ Active' if firebase_auth.initialized else '⚠️  Simulation Mode'}")
    print(f"🔗 Blockchain: {'✅ Active' if blockchain_app.is_healthy() else '❌ Error'}")
    print(f"🔐 Encryption: ✅ Active")
    print(f"🔑 Key Manager: ✅ Active")
    print(f"🌐 API Server: ✅ Starting...")
    print("=" * 50)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
