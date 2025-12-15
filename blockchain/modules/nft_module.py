"""
NFT Module - ERC-721 Implementation for DNA Samples
Each NFT represents ownership of one DNA sample
"""

import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict


@dataclass
class NFTToken:
    """NFT Token data structure"""
    token_id: str
    owner: str
    sample_id: str  # Links to DNA sample
    metadata_uri: str  # Points to Firebase metadata
    created_at: int
    approved: Optional[str] = None  # Approved address for transfer
    
    
class NFTModule:
    """ERC-721 NFT implementation for DNA samples"""
    
    def __init__(self):
        self.tokens: Dict[str, NFTToken] = {}
        self.owner_tokens: Dict[str, List[str]] = {}  # owner -> [token_ids]
        self.token_approvals: Dict[str, str] = {}  # token_id -> approved_address
        self.operator_approvals: Dict[str, Dict[str, bool]] = {}  # owner -> {operator -> approved}
        self.total_supply = 0
    
    def mint_token(self, token_id: str, owner: str, sample_id: str, 
                   metadata_uri: str) -> Dict[str, Any]:
        """Mint a new NFT token"""
        try:
            # Validate inputs
            if not token_id or not owner or not sample_id or not metadata_uri:
                return {
                    'success': False,
                    'message': 'Missing required fields'
                }
            
            # Check if token already exists
            if token_id in self.tokens:
                return {
                    'success': False,
                    'message': f'Token {token_id} already exists'
                }
            
            # Create token
            token = NFTToken(
                token_id=token_id,
                owner=owner,
                sample_id=sample_id,
                metadata_uri=metadata_uri,
                created_at=int(time.time())
            )
            
            # Store token
            self.tokens[token_id] = token
            self.total_supply += 1
            
            # Update owner index
            if owner not in self.owner_tokens:
                self.owner_tokens[owner] = []
            self.owner_tokens[owner].append(token_id)
            
            # Create event
            event = {
                'type': 'nft_minted',
                'attributes': {
                    'token_id': token_id,
                    'owner': owner,
                    'sample_id': sample_id,
                    'metadata_uri': metadata_uri,
                    'timestamp': str(token.created_at)
                }
            }
            
            return {
                'success': True,
                'message': f'NFT {token_id} minted successfully',
                'events': [event],
                'data': {
                    'token_id': token_id,
                    'owner': owner,
                    'sample_id': sample_id
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Minting failed: {str(e)}'
            }
    
    def transfer_token(self, token_id: str, from_address: str, 
                      to_address: str) -> Dict[str, Any]:
        """Transfer NFT token"""
        try:
            token = self.tokens.get(token_id)
            if not token:
                return {
                    'success': False,
                    'message': f'Token {token_id} not found'
                }
            
            # Check ownership or approval
            if token.owner != from_address:
                # Check if sender is approved
                approved = self.token_approvals.get(token_id)
                if approved != from_address:
                    # Check operator approval
                    if not self._is_approved_for_all(token.owner, from_address):
                        return {
                            'success': False,
                            'message': 'Transfer not authorized'
                        }
            
            # Perform transfer
            old_owner = token.owner
            token.owner = to_address
            
            # Update owner indexes
            if old_owner in self.owner_tokens:
                self.owner_tokens[old_owner].remove(token_id)
            
            if to_address not in self.owner_tokens:
                self.owner_tokens[to_address] = []
            self.owner_tokens[to_address].append(token_id)
            
            # Clear approvals
            if token_id in self.token_approvals:
                del self.token_approvals[token_id]
            
            # Create event
            event = {
                'type': 'nft_transferred',
                'attributes': {
                    'token_id': token_id,
                    'from': old_owner,
                    'to': to_address,
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Token {token_id} transferred to {to_address}',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Transfer failed: {str(e)}'
            }
    
    def approve_token(self, token_id: str, owner: str, 
                     approved_address: str) -> Dict[str, Any]:
        """Approve address to transfer specific token"""
        try:
            token = self.tokens.get(token_id)
            if not token:
                return {
                    'success': False,
                    'message': f'Token {token_id} not found'
                }
            
            # Check ownership
            if token.owner != owner:
                return {
                    'success': False,
                    'message': 'Only owner can approve transfers'
                }
            
            # Set approval
            if approved_address:
                self.token_approvals[token_id] = approved_address
            else:
                # Remove approval
                if token_id in self.token_approvals:
                    del self.token_approvals[token_id]
            
            # Create event
            event = {
                'type': 'nft_approval',
                'attributes': {
                    'token_id': token_id,
                    'owner': owner,
                    'approved': approved_address or '',
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Approval set for token {token_id}',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Approval failed: {str(e)}'
            }
    
    def set_approval_for_all(self, owner: str, operator: str, 
                           approved: bool) -> Dict[str, Any]:
        """Set approval for all tokens owned by owner"""
        try:
            if owner not in self.operator_approvals:
                self.operator_approvals[owner] = {}
            
            self.operator_approvals[owner][operator] = approved
            
            # Create event
            event = {
                'type': 'nft_approval_for_all',
                'attributes': {
                    'owner': owner,
                    'operator': operator,
                    'approved': str(approved),
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Operator approval set for {operator}',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Operator approval failed: {str(e)}'
            }
    
    def get_token(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Get token by ID"""
        token = self.tokens.get(token_id)
        if token:
            result = asdict(token)
            result['approved'] = self.token_approvals.get(token_id)
            return result
        return None
    
    def get_tokens_by_owner(self, owner: str) -> List[Dict[str, Any]]:
        """Get all tokens owned by an address"""
        token_ids = self.owner_tokens.get(owner, [])
        return [asdict(self.tokens[tid]) for tid in token_ids if tid in self.tokens]
    
    def get_approved(self, token_id: str) -> Optional[str]:
        """Get approved address for token"""
        return self.token_approvals.get(token_id)
    
    def is_approved_for_all(self, owner: str, operator: str) -> bool:
        """Check if operator is approved for all owner's tokens"""
        return self._is_approved_for_all(owner, operator)
    
    def _is_approved_for_all(self, owner: str, operator: str) -> bool:
        """Internal method to check operator approval"""
        return self.operator_approvals.get(owner, {}).get(operator, False)
    
    def owner_of(self, token_id: str) -> Optional[str]:
        """Get owner of token"""
        token = self.tokens.get(token_id)
        return token.owner if token else None
    
    def balance_of(self, owner: str) -> int:
        """Get number of tokens owned by address"""
        return len(self.owner_tokens.get(owner, []))
    
    def token_exists(self, token_id: str) -> bool:
        """Check if token exists"""
        return token_id in self.tokens
    
    def get_token_by_sample(self, sample_id: str) -> Optional[Dict[str, Any]]:
        """Get token associated with DNA sample"""
        for token in self.tokens.values():
            if token.sample_id == sample_id:
                return asdict(token)
        return None
    
    def burn_token(self, token_id: str, owner: str) -> Dict[str, Any]:
        """Burn (destroy) a token"""
        try:
            token = self.tokens.get(token_id)
            if not token:
                return {
                    'success': False,
                    'message': f'Token {token_id} not found'
                }
            
            # Check ownership
            if token.owner != owner:
                return {
                    'success': False,
                    'message': 'Only owner can burn token'
                }
            
            # Remove token
            del self.tokens[token_id]
            self.total_supply -= 1
            
            # Update owner index
            if owner in self.owner_tokens:
                self.owner_tokens[owner].remove(token_id)
            
            # Clear approvals
            if token_id in self.token_approvals:
                del self.token_approvals[token_id]
            
            # Create event
            event = {
                'type': 'nft_burned',
                'attributes': {
                    'token_id': token_id,
                    'owner': owner,
                    'sample_id': token.sample_id,
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Token {token_id} burned successfully',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Burn failed: {str(e)}'
            }
    
    def get_all_tokens(self) -> Dict[str, Dict[str, Any]]:
        """Get all tokens (for state hash calculation)"""
        return {tid: asdict(token) for tid, token in self.tokens.items()}
    
    def get_total_supply(self) -> int:
        """Get total number of tokens"""
        return self.total_supply