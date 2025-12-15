"""
Zero-Knowledge Proof Generator
Generates proofs using Noir circuits for DNA access system
"""

import os
import json
import subprocess
import hashlib
import secrets
from typing import Dict, Any, Optional, Tuple


class NoirProofGenerator:
    """Generates zero-knowledge proofs using Noir circuits"""
    
    def __init__(self, circuits_dir: str = "zkp/circuits"):
        self.circuits_dir = circuits_dir
        self.noir_available = self._check_noir_installation()
        
    def _check_noir_installation(self) -> bool:
        """Check if Noir is installed and available"""
        try:
            result = subprocess.run(['nargo', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✅ Noir/Nargo found:", result.stdout.strip())
                return True
            else:
                print("⚠️  Noir/Nargo not found - using simulation mode")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("⚠️  Noir/Nargo not installed - using simulation mode")
            return False
    
    def generate_access_permission_proof(self, user_secret: str, sample_id: str, 
                                       permission_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate proof for DNA sample access permission"""
        try:
            if not self.noir_available:
                return self._simulate_access_proof(user_secret, sample_id, permission_data)
            
            # Prepare circuit inputs
            circuit_inputs = self._prepare_access_inputs(user_secret, sample_id, permission_data)
            
            # Generate proof using Noir
            proof_result = self._execute_noir_prove("prove_access_permission", circuit_inputs)
            
            if proof_result['success']:
                return {
                    'success': True,
                    'proof': proof_result['proof'],
                    'public_inputs': circuit_inputs['public'],
                    'circuit_type': 'access_permission',
                    'sample_id': sample_id
                }
            else:
                return {
                    'success': False,
                    'error': proof_result['error']
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Proof generation failed: {str(e)}'
            }
    
    def generate_identity_proof(self, identity_secret: str, personal_data: Dict[str, Any], 
                              challenge: str) -> Dict[str, Any]:
        """Generate proof for identity verification"""
        try:
            if not self.noir_available:
                return self._simulate_identity_proof(identity_secret, personal_data, challenge)
            
            # Prepare circuit inputs
            circuit_inputs = self._prepare_identity_inputs(identity_secret, personal_data, challenge)
            
            # Generate proof using Noir
            proof_result = self._execute_noir_prove("verify_identity", circuit_inputs)
            
            if proof_result['success']:
                return {
                    'success': True,
                    'proof': proof_result['proof'],
                    'public_inputs': circuit_inputs['public'],
                    'circuit_type': 'identity_verification',
                    'challenge': challenge
                }
            else:
                return {
                    'success': False,
                    'error': proof_result['error']
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Identity proof generation failed: {str(e)}'
            }
    
    def _prepare_access_inputs(self, user_secret: str, sample_id: str, 
                             permission_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare inputs for access permission circuit"""
        # Hash user secret
        user_secret_hash = int(hashlib.sha256(user_secret.encode()).hexdigest(), 16) % (2**254)
        
        # Hash sample ID
        sample_id_hash = int(hashlib.sha256(sample_id.encode()).hexdigest(), 16) % (2**254)
        
        # Generate permission proof
        permission_str = json.dumps(permission_data, sort_keys=True)
        permission_proof = int(hashlib.sha256(permission_str.encode()).hexdigest(), 16) % (2**254)
        
        # Generate permission hash (public)
        permission_hash = int(hashlib.sha256(
            f"{sample_id}{permission_proof}{permission_data.get('timestamp', 0)}".encode()
        ).hexdigest(), 16) % (2**254)
        
        return {
            'private': {
                'user_secret': str(user_secret_hash),
                'permission_proof': str(permission_proof)
            },
            'public': {
                'sample_id': str(sample_id_hash),
                'permission_hash': str(permission_hash),
                'timestamp': str(permission_data.get('timestamp', int(time.time())))
            }
        }
    
    def _prepare_identity_inputs(self, identity_secret: str, personal_data: Dict[str, Any], 
                               challenge: str) -> Dict[str, Any]:
        """Prepare inputs for identity verification circuit"""
        # Hash identity secret
        identity_secret_hash = int(hashlib.sha256(identity_secret.encode()).hexdigest(), 16) % (2**254)
        
        # Hash personal data
        personal_data_str = json.dumps(personal_data, sort_keys=True)
        personal_data_hash = int(hashlib.sha256(personal_data_str.encode()).hexdigest(), 16) % (2**254)
        
        # Generate identity commitment
        identity_commitment = int(hashlib.sha256(
            f"{identity_secret_hash}{personal_data_hash}".encode()
        ).hexdigest(), 16) % (2**254)
        
        # Hash challenge
        challenge_hash = int(hashlib.sha256(challenge.encode()).hexdigest(), 16) % (2**254)
        
        # Generate response hash
        response_hash = int(hashlib.sha256(
            f"{identity_secret_hash}{challenge_hash}{personal_data_hash}".encode()
        ).hexdigest(), 16) % (2**254)
        
        return {
            'private': {
                'identity_secret': str(identity_secret_hash),
                'personal_data': str(personal_data_hash)
            },
            'public': {
                'identity_commitment': str(identity_commitment),
                'challenge': str(challenge_hash),
                'response_hash': str(response_hash)
            }
        }
    
    def _execute_noir_prove(self, circuit_name: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Noir proof generation"""
        try:
            circuit_path = os.path.join(self.circuits_dir, circuit_name)
            
            # Create Prover.toml file
            prover_toml = self._create_prover_toml(inputs)
            prover_path = os.path.join(circuit_path, "Prover.toml")
            
            with open(prover_path, 'w') as f:
                f.write(prover_toml)
            
            # Execute nargo prove
            result = subprocess.run(
                ['nargo', 'prove'],
                cwd=circuit_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Read generated proof
                proof_path = os.path.join(circuit_path, "proofs", "proof.proof")
                if os.path.exists(proof_path):
                    with open(proof_path, 'r') as f:
                        proof_data = f.read().strip()
                    
                    return {
                        'success': True,
                        'proof': proof_data
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Proof file not generated'
                    }
            else:
                return {
                    'success': False,
                    'error': f'Nargo prove failed: {result.stderr}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Noir execution failed: {str(e)}'
            }
    
    def _create_prover_toml(self, inputs: Dict[str, Any]) -> str:
        """Create Prover.toml file for Noir circuit"""
        toml_content = []
        
        # Add private inputs
        for key, value in inputs.get('private', {}).items():
            toml_content.append(f'{key} = "{value}"')
        
        # Add public inputs
        for key, value in inputs.get('public', {}).items():
            toml_content.append(f'{key} = "{value}"')
        
        return '\n'.join(toml_content)
    
    def _simulate_access_proof(self, user_secret: str, sample_id: str, 
                             permission_data: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate access permission proof generation"""
        # Generate a realistic-looking proof
        proof_data = hashlib.sha256(
            f"{user_secret}{sample_id}{json.dumps(permission_data, sort_keys=True)}".encode()
        ).hexdigest()
        
        # Prepare public inputs
        inputs = self._prepare_access_inputs(user_secret, sample_id, permission_data)
        
        return {
            'success': True,
            'proof': proof_data,
            'public_inputs': inputs['public'],
            'circuit_type': 'access_permission',
            'sample_id': sample_id,
            'simulated': True
        }
    
    def _simulate_identity_proof(self, identity_secret: str, personal_data: Dict[str, Any], 
                               challenge: str) -> Dict[str, Any]:
        """Simulate identity verification proof generation"""
        # Generate a realistic-looking proof
        proof_data = hashlib.sha256(
            f"{identity_secret}{json.dumps(personal_data, sort_keys=True)}{challenge}".encode()
        ).hexdigest()
        
        # Prepare public inputs
        inputs = self._prepare_identity_inputs(identity_secret, personal_data, challenge)
        
        return {
            'success': True,
            'proof': proof_data,
            'public_inputs': inputs['public'],
            'circuit_type': 'identity_verification',
            'challenge': challenge,
            'simulated': True
        }
    
    def generate_challenge(self) -> str:
        """Generate a random challenge for identity verification"""
        return secrets.token_hex(32)
    
    def create_user_secret(self, user_data: Dict[str, Any]) -> str:
        """Create a user secret from user data"""
        user_str = json.dumps(user_data, sort_keys=True)
        return hashlib.sha256(user_str.encode()).hexdigest()


# Add missing import
import time