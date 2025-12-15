"""
AES-256 Encryption Utilities for DNA Files
Provides secure encryption/decryption for DNA sample files
"""

import os
import base64
import hashlib
from typing import Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESCrypto:
    """AES-256 encryption/decryption handler"""
    
    def __init__(self):
        self.backend = default_backend()
        self.key_length = 32  # 256 bits
        self.iv_length = 16   # 128 bits
        self.salt_length = 16 # 128 bits
        
    def generate_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Generate AES key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(self.salt_length)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    
    def encrypt_data(self, data: bytes, password: str) -> Dict[str, Any]:
        """Encrypt data using AES-256-CBC"""
        try:
            # Generate key and salt
            key, salt = self.generate_key(password)
            
            # Generate random IV
            iv = os.urandom(self.iv_length)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            
            # Pad data to block size (16 bytes for AES)
            padded_data = self._pad_data(data)
            
            # Encrypt
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Calculate hash of original data
            data_hash = hashlib.sha256(data).hexdigest()
            
            # Encode components
            encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            
            return {
                'success': True,
                'encrypted_data': encrypted_b64,
                'iv': iv_b64,
                'salt': salt_b64,
                'data_hash': data_hash,
                'algorithm': 'AES-256-CBC',
                'key_derivation': 'PBKDF2-SHA256'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Encryption failed: {str(e)}'
            }
    
    def decrypt_data(self, encrypted_data: str, iv: str, salt: str, 
                    password: str) -> Dict[str, Any]:
        """Decrypt data using AES-256-CBC"""
        try:
            # Decode components
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            iv_bytes = base64.b64decode(iv.encode('utf-8'))
            salt_bytes = base64.b64decode(salt.encode('utf-8'))
            
            # Regenerate key
            key, _ = self.generate_key(password, salt_bytes)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv_bytes),
                backend=self.backend
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
            
            # Remove padding
            decrypted_data = self._unpad_data(padded_data)
            
            # Calculate hash for verification
            data_hash = hashlib.sha256(decrypted_data).hexdigest()
            
            return {
                'success': True,
                'decrypted_data': decrypted_data,
                'data_hash': data_hash
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Decryption failed: {str(e)}'
            }
    
    def encrypt_file(self, file_path: str, password: str, 
                    output_path: str = None) -> Dict[str, Any]:
        """Encrypt a file"""
        try:
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt data
            result = self.encrypt_data(file_data, password)
            
            if not result['success']:
                return result
            
            # Determine output path
            if output_path is None:
                output_path = file_path + '.encrypted'
            
            # Create encrypted file metadata
            metadata = {
                'original_filename': os.path.basename(file_path),
                'original_size': len(file_data),
                'encrypted_data': result['encrypted_data'],
                'iv': result['iv'],
                'salt': result['salt'],
                'data_hash': result['data_hash'],
                'algorithm': result['algorithm'],
                'key_derivation': result['key_derivation']
            }
            
            # Write encrypted file
            with open(output_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return {
                'success': True,
                'encrypted_file': output_path,
                'original_size': len(file_data),
                'encrypted_size': os.path.getsize(output_path),
                'data_hash': result['data_hash']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'File encryption failed: {str(e)}'
            }
    
    def decrypt_file(self, encrypted_file_path: str, password: str, 
                    output_path: str = None) -> Dict[str, Any]:
        """Decrypt a file"""
        try:
            # Read encrypted file metadata
            with open(encrypted_file_path, 'r') as f:
                metadata = json.load(f)
            
            # Decrypt data
            result = self.decrypt_data(
                metadata['encrypted_data'],
                metadata['iv'],
                metadata['salt'],
                password
            )
            
            if not result['success']:
                return result
            
            # Determine output path
            if output_path is None:
                output_path = metadata['original_filename']
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(result['decrypted_data'])
            
            # Verify hash
            if result['data_hash'] != metadata['data_hash']:
                return {
                    'success': False,
                    'error': 'Data integrity check failed'
                }
            
            return {
                'success': True,
                'decrypted_file': output_path,
                'original_filename': metadata['original_filename'],
                'file_size': len(result['decrypted_data']),
                'data_hash': result['data_hash']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'File decryption failed: {str(e)}'
            }
    
    def _pad_data(self, data: bytes) -> bytes:
        """Apply PKCS7 padding"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    def generate_secure_password(self, length: int = 32) -> str:
        """Generate a secure random password"""
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
    
    def hash_file(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    def verify_file_integrity(self, file_path: str, expected_hash: str) -> bool:
        """Verify file integrity using hash"""
        actual_hash = self.hash_file(file_path)
        return actual_hash == expected_hash


# Convenience functions
def encrypt_dna_file(file_path: str, password: str, output_path: str = None) -> Dict[str, Any]:
    """Encrypt a DNA file"""
    crypto = AESCrypto()
    return crypto.encrypt_file(file_path, password, output_path)


def decrypt_dna_file(encrypted_file_path: str, password: str, output_path: str = None) -> Dict[str, Any]:
    """Decrypt a DNA file"""
    crypto = AESCrypto()
    return crypto.decrypt_file(encrypted_file_path, password, output_path)


def generate_encryption_key() -> str:
    """Generate a secure encryption key"""
    crypto = AESCrypto()
    return crypto.generate_secure_password()