"""
Local Key Management for DNA Access System
Manages encryption keys securely on local system
"""

import os
import json
import hashlib
import getpass
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from .aes_crypto import AESCrypto


class KeyManager:
    """Local key management system"""
    
    def __init__(self, key_store_path: str = ".keys"):
        self.key_store_path = key_store_path
        self.crypto = AESCrypto()
        self.backend = default_backend()
        
        # Create key store directory if it doesn't exist
        if not os.path.exists(key_store_path):
            os.makedirs(key_store_path, mode=0o700)  # Secure permissions
    
    def generate_user_keypair(self, user_id: str, password: str = None) -> Dict[str, Any]:
        """Generate RSA keypair for user"""
        try:
            if password is None:
                password = getpass.getpass("Enter password for key encryption: ")
            
            # Generate RSA keypair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            
            public_key = private_key.public_key()
            
            # Serialize private key with password encryption
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save keys
            private_key_path = os.path.join(self.key_store_path, f"{user_id}_private.pem")
            public_key_path = os.path.join(self.key_store_path, f"{user_id}_public.pem")
            
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)
            os.chmod(private_key_path, 0o600)  # Owner read/write only
            
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            os.chmod(public_key_path, 0o644)  # Owner read/write, others read
            
            # Generate key fingerprint
            fingerprint = hashlib.sha256(public_pem).hexdigest()[:16]
            
            return {
                'success': True,
                'user_id': user_id,
                'private_key_path': private_key_path,
                'public_key_path': public_key_path,
                'fingerprint': fingerprint,
                'message': f'Keypair generated for user {user_id}'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Keypair generation failed: {str(e)}'
            }
    
    def load_private_key(self, user_id: str, password: str = None) -> Dict[str, Any]:
        """Load user's private key"""
        try:
            if password is None:
                password = getpass.getpass("Enter key password: ")
            
            private_key_path = os.path.join(self.key_store_path, f"{user_id}_private.pem")
            
            if not os.path.exists(private_key_path):
                return {
                    'success': False,
                    'error': f'Private key not found for user {user_id}'
                }
            
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode(),
                    backend=self.backend
                )
            
            return {
                'success': True,
                'private_key': private_key,
                'user_id': user_id
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to load private key: {str(e)}'
            }
    
    def load_public_key(self, user_id: str) -> Dict[str, Any]:
        """Load user's public key"""
        try:
            public_key_path = os.path.join(self.key_store_path, f"{user_id}_public.pem")
            
            if not os.path.exists(public_key_path):
                return {
                    'success': False,
                    'error': f'Public key not found for user {user_id}'
                }
            
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=self.backend
                )
            
            return {
                'success': True,
                'public_key': public_key,
                'user_id': user_id
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to load public key: {str(e)}'
            }
    
    def store_encryption_key(self, key_id: str, encryption_key: str, 
                           master_password: str) -> Dict[str, Any]:
        """Store an encryption key securely"""
        try:
            # Encrypt the key with master password
            key_data = {
                'key_id': key_id,
                'encryption_key': encryption_key,
                'created_at': int(time.time())
            }
            
            key_json = json.dumps(key_data)
            encrypted_result = self.crypto.encrypt_data(key_json.encode(), master_password)
            
            if not encrypted_result['success']:
                return encrypted_result
            
            # Store encrypted key
            key_file_path = os.path.join(self.key_store_path, f"{key_id}.key")
            
            with open(key_file_path, 'w') as f:
                json.dump({
                    'encrypted_data': encrypted_result['encrypted_data'],
                    'iv': encrypted_result['iv'],
                    'salt': encrypted_result['salt'],
                    'data_hash': encrypted_result['data_hash']
                }, f)
            
            os.chmod(key_file_path, 0o600)  # Owner read/write only
            
            return {
                'success': True,
                'key_id': key_id,
                'key_file': key_file_path,
                'message': f'Encryption key {key_id} stored securely'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to store encryption key: {str(e)}'
            }
    
    def retrieve_encryption_key(self, key_id: str, master_password: str) -> Dict[str, Any]:
        """Retrieve an encryption key"""
        try:
            key_file_path = os.path.join(self.key_store_path, f"{key_id}.key")
            
            if not os.path.exists(key_file_path):
                return {
                    'success': False,
                    'error': f'Encryption key {key_id} not found'
                }
            
            # Load encrypted key
            with open(key_file_path, 'r') as f:
                encrypted_key_data = json.load(f)
            
            # Decrypt key
            decrypt_result = self.crypto.decrypt_data(
                encrypted_key_data['encrypted_data'],
                encrypted_key_data['iv'],
                encrypted_key_data['salt'],
                master_password
            )
            
            if not decrypt_result['success']:
                return decrypt_result
            
            # Parse key data
            key_data = json.loads(decrypt_result['decrypted_data'].decode())
            
            return {
                'success': True,
                'key_id': key_data['key_id'],
                'encryption_key': key_data['encryption_key'],
                'created_at': key_data['created_at']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to retrieve encryption key: {str(e)}'
            }
    
    def sign_data(self, user_id: str, data: bytes, password: str = None) -> Dict[str, Any]:
        """Sign data with user's private key"""
        try:
            # Load private key
            key_result = self.load_private_key(user_id, password)
            if not key_result['success']:
                return key_result
            
            private_key = key_result['private_key']
            
            # Sign data
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return {
                'success': True,
                'signature': signature.hex(),
                'user_id': user_id,
                'data_hash': hashlib.sha256(data).hexdigest()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Signing failed: {str(e)}'
            }
    
    def verify_signature(self, user_id: str, data: bytes, signature_hex: str) -> Dict[str, Any]:
        """Verify signature with user's public key"""
        try:
            # Load public key
            key_result = self.load_public_key(user_id)
            if not key_result['success']:
                return key_result
            
            public_key = key_result['public_key']
            signature = bytes.fromhex(signature_hex)
            
            # Verify signature
            try:
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                return {
                    'success': True,
                    'valid': True,
                    'user_id': user_id,
                    'data_hash': hashlib.sha256(data).hexdigest()
                }
                
            except Exception:
                return {
                    'success': True,
                    'valid': False,
                    'user_id': user_id,
                    'message': 'Signature verification failed'
                }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Signature verification failed: {str(e)}'
            }
    
    def list_stored_keys(self) -> Dict[str, Any]:
        """List all stored keys"""
        try:
            keys = []
            
            for filename in os.listdir(self.key_store_path):
                if filename.endswith('_private.pem'):
                    user_id = filename.replace('_private.pem', '')
                    keys.append({
                        'user_id': user_id,
                        'type': 'keypair',
                        'private_key': os.path.join(self.key_store_path, filename),
                        'public_key': os.path.join(self.key_store_path, f"{user_id}_public.pem")
                    })
                elif filename.endswith('.key'):
                    key_id = filename.replace('.key', '')
                    keys.append({
                        'key_id': key_id,
                        'type': 'encryption_key',
                        'key_file': os.path.join(self.key_store_path, filename)
                    })
            
            return {
                'success': True,
                'keys': keys,
                'total_count': len(keys)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to list keys: {str(e)}'
            }
    
    def delete_key(self, key_identifier: str) -> Dict[str, Any]:
        """Delete a key (keypair or encryption key)"""
        try:
            deleted_files = []
            
            # Check for keypair
            private_key_path = os.path.join(self.key_store_path, f"{key_identifier}_private.pem")
            public_key_path = os.path.join(self.key_store_path, f"{key_identifier}_public.pem")
            
            if os.path.exists(private_key_path):
                os.remove(private_key_path)
                deleted_files.append(private_key_path)
            
            if os.path.exists(public_key_path):
                os.remove(public_key_path)
                deleted_files.append(public_key_path)
            
            # Check for encryption key
            key_file_path = os.path.join(self.key_store_path, f"{key_identifier}.key")
            if os.path.exists(key_file_path):
                os.remove(key_file_path)
                deleted_files.append(key_file_path)
            
            if not deleted_files:
                return {
                    'success': False,
                    'error': f'No keys found for identifier: {key_identifier}'
                }
            
            return {
                'success': True,
                'deleted_files': deleted_files,
                'message': f'Deleted {len(deleted_files)} key files'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to delete key: {str(e)}'
            }


# Add missing import
import time