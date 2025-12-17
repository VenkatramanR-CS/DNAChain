"""
Pydantic models for DNA Access System API
"""

from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


class DNASampleUpload(BaseModel):
    """DNA sample upload request"""
    sample_id: str = Field(..., description="Unique sample identifier")
    owner: str = Field(..., description="Owner wallet address")
    file_data: str = Field(..., description="Base64 encoded file data")
    password: str = Field(..., description="Encryption password")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sample metadata")


class DNASampleResponse(BaseModel):
    """DNA sample response"""
    sample_id: str
    owner: str
    cid: str
    file_hash: str
    metadata: Dict[str, Any]
    timestamp: int
    status: str


class NFTMintRequest(BaseModel):
    """NFT minting request"""
    token_id: str = Field(..., description="Unique token identifier")
    sample_id: str = Field(..., description="Associated DNA sample ID")
    owner: str = Field(..., description="Token owner address")
    metadata_uri: str = Field(..., description="Metadata URI")


class NFTResponse(BaseModel):
    """NFT response"""
    token_id: str
    owner: str
    sample_id: str
    metadata_uri: str
    created_at: int
    approved: Optional[str] = None


class AccessRequest(BaseModel):
    """Access request"""
    requester: str = Field(..., description="Requester wallet address")
    sample_id: str = Field(..., description="DNA sample ID")
    purpose: str = Field(..., description="Purpose of access")
    expiry_hours: int = Field(default=24, description="Request expiry in hours")


class AccessRequestResponse(BaseModel):
    """Access request response"""
    request_id: str
    requester: str
    sample_id: str
    purpose: str
    status: str
    created_at: int
    updated_at: int
    approvals: List[str]
    required_approvals: int
    expiry_time: Optional[int] = None


class ZKProofRequest(BaseModel):
    """Zero-knowledge proof request"""
    proof: str = Field(..., description="Serialized proof data")
    public_inputs: Dict[str, Any] = Field(..., description="Public inputs")
    request_id: str = Field(..., description="Associated request ID")
    circuit_type: str = Field(default="access_permission", description="Circuit type")


class ZKProofResponse(BaseModel):
    """Zero-knowledge proof response"""
    proof_id: str
    prover: str
    circuit_type: str
    verified: bool
    created_at: int
    verified_at: Optional[int] = None


class MultiSigProposal(BaseModel):
    """Multi-signature proposal"""
    proposer: str = Field(..., description="Proposer address")
    proposal_type: str = Field(..., description="Type of proposal")
    target_data: Dict[str, Any] = Field(..., description="Proposal data")
    required_signatures: Optional[int] = Field(default=None, description="Required signatures")


class MultiSigProposalResponse(BaseModel):
    """Multi-signature proposal response"""
    proposal_id: str
    proposer: str
    proposal_type: str
    target_data: Dict[str, Any]
    required_signatures: int
    signatures: List[str]
    status: str
    created_at: int
    expiry_time: int
    executed_at: Optional[int] = None


class TransactionRequest(BaseModel):
    """Generic transaction request"""
    tx_type: str = Field(..., description="Transaction type")
    sender: str = Field(..., description="Sender address")
    data: Dict[str, Any] = Field(..., description="Transaction data")


class TransactionResponse(BaseModel):
    """Transaction response"""
    success: bool
    message: str
    tx_hash: Optional[str] = None
    events: List[Dict[str, Any]] = Field(default_factory=list)
    data: Optional[Dict[str, Any]] = None


class QueryRequest(BaseModel):
    """Query request"""
    path: str = Field(..., description="Query path")
    data: str = Field(default="", description="Query data")


class QueryResponse(BaseModel):
    """Query response"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    message: str


class EncryptionRequest(BaseModel):
    """File encryption request"""
    file_data: str = Field(..., description="Base64 encoded file data")
    password: str = Field(..., description="Encryption password")
    filename: str = Field(..., description="Original filename")


class EncryptionResponse(BaseModel):
    """File encryption response"""
    success: bool
    encrypted_data: Optional[str] = None
    iv: Optional[str] = None
    salt: Optional[str] = None
    data_hash: Optional[str] = None
    error: Optional[str] = None


class DecryptionRequest(BaseModel):
    """File decryption request"""
    encrypted_data: str = Field(..., description="Encrypted data")
    iv: str = Field(..., description="Initialization vector")
    salt: str = Field(..., description="Salt")
    password: str = Field(..., description="Decryption password")


class DecryptionResponse(BaseModel):
    """File decryption response"""
    success: bool
    decrypted_data: Optional[str] = None
    data_hash: Optional[str] = None
    error: Optional[str] = None


class KeyGenerationRequest(BaseModel):
    """Key generation request"""
    user_id: str = Field(..., description="User identifier")
    password: str = Field(..., description="Key encryption password")


class KeyGenerationResponse(BaseModel):
    """Key generation response"""
    success: bool
    user_id: Optional[str] = None
    fingerprint: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None


class SignatureRequest(BaseModel):
    """Digital signature request"""
    user_id: str = Field(..., description="Signer user ID")
    data: str = Field(..., description="Base64 encoded data to sign")
    password: str = Field(..., description="Private key password")


class SignatureResponse(BaseModel):
    """Digital signature response"""
    success: bool
    signature: Optional[str] = None
    user_id: Optional[str] = None
    data_hash: Optional[str] = None
    error: Optional[str] = None


class VerificationRequest(BaseModel):
    """Signature verification request"""
    user_id: str = Field(..., description="Signer user ID")
    data: str = Field(..., description="Base64 encoded original data")
    signature: str = Field(..., description="Signature to verify")


class VerificationResponse(BaseModel):
    """Signature verification response"""
    success: bool
    valid: Optional[bool] = None
    user_id: Optional[str] = None
    data_hash: Optional[str] = None
    error: Optional[str] = None


class SystemStatus(BaseModel):
    """System status response"""
    blockchain_status: str
    total_samples: int
    total_nfts: int
    pending_requests: int
    verified_proofs: int
    active_proposals: int
    uptime: str


class UserRegistration(BaseModel):
    """User registration request"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="User password")
    display_name: str = Field(..., description="User display name")
    role: str = Field(default="user", description="User role")


class UserLogin(BaseModel):
    """User login request"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")


class UserProfile(BaseModel):
    """User profile"""
    uid: str
    email: str
    display_name: str
    role: str
    created_at: datetime
    last_login: Optional[datetime] = None
    wallet_address: Optional[str] = None
    verified: bool = False


class AuthResponse(BaseModel):
    """Authentication response"""
    success: bool
    user: Optional[UserProfile] = None
    token: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None


class SampleMetadata(BaseModel):
    """DNA sample metadata"""
    sample_type: str
    collection_date: Optional[str] = None
    patient_id: Optional[str] = None
    lab_id: Optional[str] = None
    quality_score: Optional[float] = None
    notes: Optional[str] = None


class AdvancedDNAUpload(BaseModel):
    """Advanced DNA sample upload with Firebase"""
    sample_id: str = Field(..., description="Unique sample identifier")
    owner_uid: str = Field(..., description="Owner Firebase UID")
    file_data: str = Field(..., description="Base64 encoded file data")
    filename: str = Field(..., description="Original filename")
    password: str = Field(..., description="Encryption password")
    metadata: SampleMetadata = Field(..., description="Sample metadata")


class AccessApproval(BaseModel):
    """Access request approval/denial"""
    request_id: str = Field(..., description="Request ID")
    approver_uid: str = Field(..., description="Approver Firebase UID")
    action: str = Field(..., description="approve or deny")
    reason: Optional[str] = Field(None, description="Reason for decision")


class NFTTransfer(BaseModel):
    """NFT transfer request"""
    token_id: str = Field(..., description="Token ID")
    from_uid: str = Field(..., description="Current owner UID")
    to_uid: str = Field(..., description="New owner UID")
    password: str = Field(..., description="Owner's password for verification")


class BatchZKPVerification(BaseModel):
    """Batch ZKP verification request"""
    proofs: List[ZKProofRequest] = Field(..., description="List of proofs to verify")


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    detail: Optional[str] = None
    code: Optional[int] = None