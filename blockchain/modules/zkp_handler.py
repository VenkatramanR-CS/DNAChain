"""
Zero-Knowledge Proof Handler Module
Handles ZKP verification for access permissions using Noir circuits
"""

import json
import time
import hashlib
import subprocess
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict


@dataclass
class ZKProof:
    """Zero-knowledge proof data structure"""
    proof_id: str
    prover: str
    circuit_type: str
    proof_data: str  # Serialized proof
    public_inputs: Dict[str, Any]
    verified: bool
    created_at: int
    verified_at: Optional[int] = None


class ZKPHandler:
    """Zero-Knowledge Proof verification handler"""
    
    def __init__(self):
        self.proofs: Dict[str, ZKProof] = {}
        self.circuit_paths = {
            'access_permission': './zkp/circuits/prove_access_permission.nr',
            'identity_verification': './zkp/circuits/verify_identity.nr'
        }
        self.verification_keys = {}  # Would store circuit verification keys
        
    def verify_proof(self, proof: str, public_inputs: Dict[str, Any], 
                    request_id: str, circuit_type: str = 'access_permission') -> Dict[str, Any]:
        """Verify a zero-knowledge proof"""
        try:
            # Validate inputs
            if not proof or not public_inputs or not request_id:
                return {
                    'success': False,
                    'message': 'Missing required fields for proof verification'
                }
            
            # Check if circuit type is supported
            if circuit_type not in self.circuit_paths:
                return {
                    'success': False,
                    'message': f'Unsupported circuit type: {circuit_type}'
                }
            
            # Generate proof ID
            proof_id = hashlib.sha256(
                f"{proof}{json.dumps(public_inputs, sort_keys=True)}{time.time()}".encode()
            ).hexdigest()[:16]
            
            # Verify the proof (simplified for MVP)
            verification_result = self._verify_noir_proof(
                proof, public_inputs, circuit_type
            )
            
            # Create proof record
            zkp_proof = ZKProof(
                proof_id=proof_id,
                prover=public_inputs.get('prover', 'unknown'),
                circuit_type=circuit_type,
                proof_data=proof,
                public_inputs=public_inputs,
                verified=verification_result['valid'],
                created_at=int(time.time()),
                verified_at=int(time.time()) if verification_result['valid'] else None
            )
            
            # Store proof
            self.proofs[proof_id] = zkp_proof
            
            # Create event
            event = {
                'type': 'zkp_verified' if verification_result['valid'] else 'zkp_verification_failed',
                'attributes': {
                    'proof_id': proof_id,
                    'prover': zkp_proof.prover,
                    'circuit_type': circuit_type,
                    'request_id': request_id,
                    'verified': str(verification_result['valid']),
                    'timestamp': str(zkp_proof.created_at)
                }
            }
            
            return {
                'success': verification_result['valid'],
                'message': verification_result['message'],
                'events': [event],
                'data': {
                    'proof_id': proof_id,
                    'verified': verification_result['valid'],
                    'request_id': request_id
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Proof verification failed: {str(e)}'
            }
    
    def _verify_noir_proof(self, proof: str, public_inputs: Dict[str, Any], 
                          circuit_type: str) -> Dict[str, Any]:
        """Verify proof using Noir circuit (simplified implementation)"""
        try:
            # In a real implementation, this would:
            # 1. Load the circuit verification key
            # 2. Parse the proof data
            # 3. Call Noir's verification function
            # 4. Return the verification result
            
            # For MVP, we'll do basic validation
            if not proof or len(proof) < 10:
                return {
                    'valid': False,
                    'message': 'Invalid proof format'
                }
            
            # Check required public inputs for access permission circuit
            if circuit_type == 'access_permission':
                required_inputs = ['user_id', 'sample_id', 'permission_hash']
                for input_key in required_inputs:
                    if input_key not in public_inputs:
                        return {
                            'valid': False,
                            'message': f'Missing required public input: {input_key}'
                        }
            
            # Simulate proof verification (replace with actual Noir verification)
            # This is a placeholder - in production you'd call the actual Noir verifier
            is_valid = self._simulate_proof_verification(proof, public_inputs, circuit_type)
            
            return {
                'valid': is_valid,
                'message': 'Proof verified successfully' if is_valid else 'Proof verification failed'
            }
            
        except Exception as e:
            return {
                'valid': False,
                'message': f'Verification error: {str(e)}'
            }
    
    def _simulate_proof_verification(self, proof: str, public_inputs: Dict[str, Any], 
                                   circuit_type: str) -> bool:
        """Simulate proof verification for MVP (replace with actual Noir verification)"""
        try:
            # Basic checks for demonstration
            if circuit_type == 'access_permission':
                # Check if proof contains expected structure
                if 'user_id' in public_inputs and 'sample_id' in public_inputs:
                    # Simulate successful verification for valid-looking inputs
                    user_id = public_inputs['user_id']
                    sample_id = public_inputs['sample_id']
                    
                    # Simple validation: proof should be hex string of reasonable length
                    if len(proof) >= 64 and all(c in '0123456789abcdef' for c in proof.lower()):
                        return True
            
            return False
            
        except Exception:
            return False
    
    def generate_proof_request(self, user_id: str, sample_id: str, 
                             permission_type: str) -> Dict[str, Any]:
        """Generate a proof request for client to fulfill"""
        try:
            # Create proof request with required inputs
            proof_request = {
                'circuit_type': 'access_permission',
                'public_inputs': {
                    'user_id': user_id,
                    'sample_id': sample_id,
                    'permission_type': permission_type,
                    'timestamp': int(time.time())
                },
                'private_inputs': {
                    'user_secret': 'REQUIRED',  # Client must provide
                    'permission_proof': 'REQUIRED'  # Client must provide
                },
                'circuit_path': self.circuit_paths.get('access_permission', ''),
                'instructions': 'Generate proof using Noir circuit with provided inputs'
            }
            
            return {
                'success': True,
                'message': 'Proof request generated',
                'data': proof_request
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Proof request generation failed: {str(e)}'
            }
    
    def get_proof(self, proof_id: str) -> Optional[Dict[str, Any]]:
        """Get proof by ID"""
        proof = self.proofs.get(proof_id)
        if proof:
            return asdict(proof)
        return None
    
    def get_proofs_by_prover(self, prover: str) -> List[Dict[str, Any]]:
        """Get all proofs by prover"""
        results = []
        for proof in self.proofs.values():
            if proof.prover == prover:
                results.append(asdict(proof))
        return results
    
    def get_verified_proofs(self) -> List[Dict[str, Any]]:
        """Get all verified proofs"""
        results = []
        for proof in self.proofs.values():
            if proof.verified:
                results.append(asdict(proof))
        return results
    
    def validate_circuit_inputs(self, circuit_type: str, 
                              inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate inputs for a specific circuit type"""
        try:
            if circuit_type == 'access_permission':
                required = ['user_id', 'sample_id', 'permission_hash']
                missing = [field for field in required if field not in inputs]
                
                if missing:
                    return {
                        'valid': False,
                        'message': f'Missing required inputs: {missing}'
                    }
                
                # Additional validation
                if not isinstance(inputs['user_id'], str) or len(inputs['user_id']) < 1:
                    return {
                        'valid': False,
                        'message': 'Invalid user_id format'
                    }
                
                if not isinstance(inputs['sample_id'], str) or len(inputs['sample_id']) < 1:
                    return {
                        'valid': False,
                        'message': 'Invalid sample_id format'
                    }
                
                return {
                    'valid': True,
                    'message': 'Inputs valid for access_permission circuit'
                }
            
            elif circuit_type == 'identity_verification':
                required = ['identity_hash', 'challenge']
                missing = [field for field in required if field not in inputs]
                
                if missing:
                    return {
                        'valid': False,
                        'message': f'Missing required inputs: {missing}'
                    }
                
                return {
                    'valid': True,
                    'message': 'Inputs valid for identity_verification circuit'
                }
            
            else:
                return {
                    'valid': False,
                    'message': f'Unknown circuit type: {circuit_type}'
                }
                
        except Exception as e:
            return {
                'valid': False,
                'message': f'Input validation failed: {str(e)}'
            }
    
    def get_circuit_info(self, circuit_type: str) -> Dict[str, Any]:
        """Get information about a circuit"""
        if circuit_type not in self.circuit_paths:
            return {
                'success': False,
                'message': f'Circuit type {circuit_type} not found'
            }
        
        circuit_info = {
            'circuit_type': circuit_type,
            'circuit_path': self.circuit_paths[circuit_type],
            'description': self._get_circuit_description(circuit_type),
            'required_public_inputs': self._get_required_inputs(circuit_type),
            'required_private_inputs': self._get_required_private_inputs(circuit_type)
        }
        
        return {
            'success': True,
            'data': circuit_info
        }
    
    def _get_circuit_description(self, circuit_type: str) -> str:
        """Get description for circuit type"""
        descriptions = {
            'access_permission': 'Proves user has permission to access DNA sample without revealing identity',
            'identity_verification': 'Proves identity without revealing personal information'
        }
        return descriptions.get(circuit_type, 'No description available')
    
    def _get_required_inputs(self, circuit_type: str) -> List[str]:
        """Get required public inputs for circuit"""
        inputs = {
            'access_permission': ['user_id', 'sample_id', 'permission_hash'],
            'identity_verification': ['identity_hash', 'challenge']
        }
        return inputs.get(circuit_type, [])
    
    def _get_required_private_inputs(self, circuit_type: str) -> List[str]:
        """Get required private inputs for circuit"""
        inputs = {
            'access_permission': ['user_secret', 'permission_proof'],
            'identity_verification': ['identity_secret', 'response']
        }
        return inputs.get(circuit_type, [])
    
    def get_proof_statistics(self) -> Dict[str, Any]:
        """Get statistics about proofs"""
        total_proofs = len(self.proofs)
        verified_proofs = sum(1 for p in self.proofs.values() if p.verified)
        failed_proofs = total_proofs - verified_proofs
        
        circuit_stats = {}
        for proof in self.proofs.values():
            circuit_type = proof.circuit_type
            if circuit_type not in circuit_stats:
                circuit_stats[circuit_type] = {'total': 0, 'verified': 0}
            circuit_stats[circuit_type]['total'] += 1
            if proof.verified:
                circuit_stats[circuit_type]['verified'] += 1
        
        return {
            'total_proofs': total_proofs,
            'verified_proofs': verified_proofs,
            'failed_proofs': failed_proofs,
            'verification_rate': verified_proofs / total_proofs if total_proofs > 0 else 0,
            'circuit_statistics': circuit_stats
        }
    
    def cleanup_expired_proofs(self, max_age_hours: int = 24) -> Dict[str, Any]:
        """Clean up old proofs to save storage"""
        try:
            current_time = int(time.time())
            max_age_seconds = max_age_hours * 3600
            
            expired_proofs = []
            for proof_id, proof in list(self.proofs.items()):
                if current_time - proof.created_at > max_age_seconds:
                    expired_proofs.append(proof_id)
                    del self.proofs[proof_id]
            
            return {
                'success': True,
                'message': f'Cleaned up {len(expired_proofs)} expired proofs',
                'data': {
                    'cleaned_count': len(expired_proofs),
                    'remaining_count': len(self.proofs)
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Cleanup failed: {str(e)}'
            }