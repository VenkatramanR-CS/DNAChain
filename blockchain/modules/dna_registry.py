"""
DNA Sample Registry Module
Manages registration and tracking of DNA samples on the blockchain
"""

import time
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict


@dataclass
class DNASample:
    """DNA Sample data structure"""
    sample_id: str
    owner: str
    cid: str  # IPFS Content Identifier
    file_hash: str  # SHA-256 hash of encrypted file
    metadata: Dict[str, Any]
    timestamp: int
    status: str = "active"  # active, revoked, transferred


class DNARegistry:
    """DNA Sample Registry implementation"""
    
    def __init__(self):
        self.samples: Dict[str, DNASample] = {}
        self.owner_samples: Dict[str, List[str]] = {}  # owner -> [sample_ids]
    
    def register_sample(self, sample_id: str, owner: str, cid: str, 
                       file_hash: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Register a new DNA sample"""
        try:
            # Validate inputs
            if not sample_id or not owner or not cid or not file_hash:
                return {
                    'success': False,
                    'message': 'Missing required fields'
                }
            
            # Check if sample already exists
            if sample_id in self.samples:
                return {
                    'success': False,
                    'message': f'Sample {sample_id} already exists'
                }
            
            # Validate file hash format (should be SHA-256)
            if len(file_hash) != 64:
                return {
                    'success': False,
                    'message': 'Invalid file hash format'
                }
            
            # Create sample
            sample = DNASample(
                sample_id=sample_id,
                owner=owner,
                cid=cid,
                file_hash=file_hash,
                metadata=metadata or {},
                timestamp=int(time.time())
            )
            
            # Store sample
            self.samples[sample_id] = sample
            
            # Update owner index
            if owner not in self.owner_samples:
                self.owner_samples[owner] = []
            self.owner_samples[owner].append(sample_id)
            
            # Create event
            event = {
                'type': 'dna_sample_registered',
                'attributes': {
                    'sample_id': sample_id,
                    'owner': owner,
                    'cid': cid,
                    'timestamp': str(sample.timestamp)
                }
            }
            
            return {
                'success': True,
                'message': f'DNA sample {sample_id} registered successfully',
                'events': [event],
                'data': {
                    'sample_id': sample_id,
                    'owner': owner,
                    'cid': cid
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Registration failed: {str(e)}'
            }
    
    def get_sample(self, sample_id: str) -> Optional[Dict[str, Any]]:
        """Get DNA sample by ID"""
        sample = self.samples.get(sample_id)
        if sample:
            return asdict(sample)
        return None
    
    def get_samples_by_owner(self, owner: str) -> List[Dict[str, Any]]:
        """Get all samples owned by an address"""
        sample_ids = self.owner_samples.get(owner, [])
        return [asdict(self.samples[sid]) for sid in sample_ids if sid in self.samples]
    
    def update_sample_status(self, sample_id: str, new_status: str, 
                           requester: str) -> Dict[str, Any]:
        """Update sample status (only owner can update)"""
        try:
            sample = self.samples.get(sample_id)
            if not sample:
                return {
                    'success': False,
                    'message': f'Sample {sample_id} not found'
                }
            
            # Check ownership
            if sample.owner != requester:
                return {
                    'success': False,
                    'message': 'Only owner can update sample status'
                }
            
            # Validate status
            valid_statuses = ['active', 'revoked', 'transferred']
            if new_status not in valid_statuses:
                return {
                    'success': False,
                    'message': f'Invalid status. Must be one of: {valid_statuses}'
                }
            
            # Update status
            old_status = sample.status
            sample.status = new_status
            
            # Create event
            event = {
                'type': 'dna_sample_status_updated',
                'attributes': {
                    'sample_id': sample_id,
                    'old_status': old_status,
                    'new_status': new_status,
                    'owner': sample.owner,
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Sample {sample_id} status updated to {new_status}',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Status update failed: {str(e)}'
            }
    
    def transfer_sample(self, sample_id: str, from_owner: str, 
                       to_owner: str) -> Dict[str, Any]:
        """Transfer sample ownership"""
        try:
            sample = self.samples.get(sample_id)
            if not sample:
                return {
                    'success': False,
                    'message': f'Sample {sample_id} not found'
                }
            
            # Check current ownership
            if sample.owner != from_owner:
                return {
                    'success': False,
                    'message': 'Invalid current owner'
                }
            
            # Update ownership
            sample.owner = to_owner
            sample.status = 'transferred'
            
            # Update owner indexes
            if from_owner in self.owner_samples:
                self.owner_samples[from_owner].remove(sample_id)
            
            if to_owner not in self.owner_samples:
                self.owner_samples[to_owner] = []
            self.owner_samples[to_owner].append(sample_id)
            
            # Create event
            event = {
                'type': 'dna_sample_transferred',
                'attributes': {
                    'sample_id': sample_id,
                    'from_owner': from_owner,
                    'to_owner': to_owner,
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Sample {sample_id} transferred to {to_owner}',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Transfer failed: {str(e)}'
            }
    
    def verify_sample_integrity(self, sample_id: str, 
                               provided_hash: str) -> Dict[str, Any]:
        """Verify sample file integrity"""
        sample = self.samples.get(sample_id)
        if not sample:
            return {
                'success': False,
                'message': f'Sample {sample_id} not found'
            }
        
        is_valid = sample.file_hash == provided_hash
        
        return {
            'success': True,
            'message': 'Integrity check completed',
            'data': {
                'sample_id': sample_id,
                'is_valid': is_valid,
                'stored_hash': sample.file_hash,
                'provided_hash': provided_hash
            }
        }
    
    def get_all_samples(self) -> Dict[str, Dict[str, Any]]:
        """Get all samples (for state hash calculation)"""
        return {sid: asdict(sample) for sid, sample in self.samples.items()}
    
    def get_sample_count(self) -> int:
        """Get total number of registered samples"""
        return len(self.samples)
    
    def search_samples(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search samples by metadata or other criteria"""
        results = []
        
        for sample in self.samples.values():
            match = True
            
            # Check owner filter
            if 'owner' in query and sample.owner != query['owner']:
                match = False
            
            # Check status filter
            if 'status' in query and sample.status != query['status']:
                match = False
            
            # Check metadata filters
            if 'metadata' in query:
                for key, value in query['metadata'].items():
                    if key not in sample.metadata or sample.metadata[key] != value:
                        match = False
                        break
            
            if match:
                results.append(asdict(sample))
        
        return results