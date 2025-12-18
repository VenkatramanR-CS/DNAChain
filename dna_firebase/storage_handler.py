"""
Firebase Storage Handler for DNA Files
Manages encrypted DNA file storage in Firebase Cloud Storage
"""

import os
import json
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
try:
    import firebase_admin  # type: ignore
    from firebase_admin import credentials, storage  # type: ignore
    from google.cloud import storage as gcs  # type: ignore
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False
    print("⚠️  Firebase libraries not installed - running in simulation mode")


class FirebaseStorageHandler:
    """Firebase Cloud Storage handler for DNA files"""
    
    def __init__(self, config_path: str = "dna_firebase/config.json", bucket_name: Optional[str] = None):
        self.config_path = config_path
        self.bucket_name = bucket_name or "dnachain-643f8.appspot.com"  # Try default bucket format
        self.bucket = None
        self.initialized = False
        
        # Initialize Firebase (with fallback for demo)
        self._initialize_firebase()
    
    def _initialize_firebase(self):
        """Initialize Firebase Admin SDK"""
        try:
            if not FIREBASE_AVAILABLE:
                print("⚠️  Firebase libraries not available - running in simulation mode")
                self.initialized = False
                return
                
            # Check if Firebase is already initialized (by auth module)
            if firebase_admin._apps:
                # Firebase already initialized, just get the storage bucket
                try:
                    # Try to get the bucket with error handling for version conflicts
                    self.bucket = storage.bucket()
                    self.initialized = True
                    print("✅ Firebase Storage connected to existing app")
                    return
                except Exception as e:
                    # Handle specific version conflicts gracefully
                    error_msg = str(e).lower()
                    if 'extra_headers' in error_msg or 'unexpected keyword argument' in error_msg:
                        print(f"⚠️  Firebase Storage version conflict detected: {e}")
                        print("📝 This is likely due to Firebase Admin SDK version compatibility")
                        print("📝 Running storage in simulation mode")
                    else:
                        print(f"⚠️  Firebase Storage connection failed: {e}")
                        print("📝 Running storage in simulation mode")
                    self.initialized = False
                    return
            
            # Firebase not initialized yet, initialize it
            if os.path.exists(self.config_path):
                try:
                    cred = credentials.Certificate(self.config_path)
                    
                    # Try different bucket name formats
                    bucket_names = [
                        "dnachain-643f8.appspot.com",
                        "dnachain-643f8.firebasestorage.app", 
                        "dnachain-643f8"
                    ]
                    
                    for bucket_name in bucket_names:
                        try:
                            firebase_admin.initialize_app(cred, {
                                'storageBucket': bucket_name
                            })
                            self.bucket = storage.bucket()
                            self.bucket_name = bucket_name
                            self.initialized = True
                            print(f"✅ Firebase Storage initialized successfully with bucket: {bucket_name}")
                            return
                        except Exception as bucket_error:
                            print(f"⚠️  Failed to connect to bucket {bucket_name}: {bucket_error}")
                            # Reset Firebase app for next attempt
                            if firebase_admin._apps:
                                del firebase_admin._apps[firebase_admin._DEFAULT_APP_NAME]
                            continue
                    
                    # If all bucket attempts failed
                    raise Exception("All bucket name attempts failed")
                except Exception as init_error:
                    # Handle specific version conflicts gracefully
                    error_msg = str(init_error).lower()
                    if 'extra_headers' in error_msg or 'unexpected keyword argument' in error_msg:
                        print(f"⚠️  Firebase Storage version conflict detected: {init_error}")
                        print("📝 This is likely due to Firebase Admin SDK version compatibility")
                        print("📝 Running storage in simulation mode")
                    else:
                        print(f"⚠️  Firebase Storage initialization failed: {init_error}")
                        print("📝 Running storage in simulation mode")
                    self.initialized = False
            else:
                # Demo mode: Simulate Firebase
                print("⚠️  Firebase config not found - running in simulation mode")
                self.initialized = False
                
        except Exception as e:
            print(f"⚠️  Firebase initialization failed: {e}")
            print("📝 Running in simulation mode")
            self.initialized = False
    
    def upload_encrypted_file(self, file_data: bytes, file_path: str, 
                            metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Upload encrypted file to Firebase Storage"""
        try:
            if not self.initialized or self.bucket is None:
                return self._simulate_upload(file_data, file_path, metadata)
            
            # Create blob reference
            blob = self.bucket.blob(file_path)
            
            # Set metadata
            if metadata:
                blob.metadata = metadata
            
            # Upload file with correct content type
            blob.upload_from_string(
                file_data,
                content_type='application/octet-stream'
            )
            
            # Generate download URL (with expiration)
            download_url = blob.generate_signed_url(
                expiration=datetime.utcnow() + timedelta(hours=24),
                method='GET'
            )
            
            # Calculate file hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            return {
                'success': True,
                'file_path': file_path,
                'download_url': download_url,
                'file_hash': file_hash,
                'file_size': len(file_data),
                'upload_time': datetime.utcnow().isoformat(),
                'metadata': metadata or {}
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Upload failed: {str(e)}'
            }
    
    def download_encrypted_file(self, file_path: str) -> Dict[str, Any]:
        """Download encrypted file from Firebase Storage"""
        try:
            if not self.initialized or self.bucket is None:
                return self._simulate_download(file_path)
            
            # Get blob reference
            blob = self.bucket.blob(file_path)
            
            # Check if file exists
            if not blob.exists():
                return {
                    'success': False,
                    'error': f'File not found: {file_path}'
                }
            
            # Download file data
            file_data = blob.download_as_bytes()
            
            # Get metadata
            blob.reload()
            metadata = blob.metadata or {}
            
            # Calculate file hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            return {
                'success': True,
                'file_data': file_data,
                'file_path': file_path,
                'file_hash': file_hash,
                'file_size': len(file_data),
                'metadata': metadata,
                'last_modified': blob.updated.isoformat() if blob.updated else None
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Download failed: {str(e)}'
            }
    
    def delete_file(self, file_path: str) -> Dict[str, Any]:
        """Delete file from Firebase Storage"""
        try:
            if not self.initialized or self.bucket is None:
                return self._simulate_delete(file_path)
            
            # Get blob reference
            blob = self.bucket.blob(file_path)
            
            # Check if file exists
            if not blob.exists():
                return {
                    'success': False,
                    'error': f'File not found: {file_path}'
                }
            
            # Delete file
            blob.delete()
            
            return {
                'success': True,
                'message': f'File deleted: {file_path}',
                'deleted_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Delete failed: {str(e)}'
            }
    
    def list_files(self, prefix: str = "", limit: int = 100) -> Dict[str, Any]:
        """List files in Firebase Storage"""
        try:
            if not self.initialized or self.bucket is None:
                return self._simulate_list(prefix, limit)
            
            # List blobs with prefix
            blobs = self.bucket.list_blobs(prefix=prefix, max_results=limit)
            
            files = []
            for blob in blobs:
                files.append({
                    'name': blob.name,
                    'size': blob.size,
                    'created': blob.time_created.isoformat() if blob.time_created else None,
                    'updated': blob.updated.isoformat() if blob.updated else None,
                    'content_type': blob.content_type,
                    'metadata': blob.metadata or {}
                })
            
            return {
                'success': True,
                'files': files,
                'count': len(files),
                'prefix': prefix
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'List failed: {str(e)}'
            }
    
    def get_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """Get file metadata without downloading"""
        try:
            if not self.initialized or self.bucket is None:
                return self._simulate_metadata(file_path)
            
            # Get blob reference
            blob = self.bucket.blob(file_path)
            
            # Check if file exists
            if not blob.exists():
                return {
                    'success': False,
                    'error': f'File not found: {file_path}'
                }
            
            # Reload to get latest metadata
            blob.reload()
            
            return {
                'success': True,
                'file_path': file_path,
                'size': blob.size,
                'content_type': blob.content_type,
                'created': blob.time_created.isoformat() if blob.time_created else None,
                'updated': blob.updated.isoformat() if blob.updated else None,
                'metadata': blob.metadata or {},
                'etag': blob.etag
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Metadata retrieval failed: {str(e)}'
            }
    
    def generate_upload_url(self, file_path: str, expiration_hours: int = 1) -> Dict[str, Any]:
        """Generate signed URL for direct upload"""
        try:
            if not self.initialized or self.bucket is None:
                return self._simulate_upload_url(file_path, expiration_hours)
            
            # Create blob reference
            blob = self.bucket.blob(file_path)
            
            # Generate signed URL for PUT operation
            upload_url = blob.generate_signed_url(
                expiration=datetime.utcnow() + timedelta(hours=expiration_hours),
                method='PUT',
                content_type='application/octet-stream'
            )
            
            return {
                'success': True,
                'upload_url': upload_url,
                'file_path': file_path,
                'expires_at': (datetime.utcnow() + timedelta(hours=expiration_hours)).isoformat(),
                'method': 'PUT'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'URL generation failed: {str(e)}'
            }
    
    def _simulate_upload(self, file_data: bytes, file_path: str, metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Simulate file upload for demo mode"""
        file_hash = hashlib.sha256(file_data).hexdigest()
        return {
            'success': True,
            'file_path': file_path,
            'download_url': f'https://simulated-storage.com/{file_path}',
            'file_hash': file_hash,
            'file_size': len(file_data),
            'upload_time': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
            'simulated': True
        }
    
    def _simulate_download(self, file_path: str) -> Dict[str, Any]:
        """Simulate file download for demo mode"""
        # Simulate some DNA data
        simulated_data = b"SIMULATED_ENCRYPTED_DNA_DATA_" + file_path.encode()
        file_hash = hashlib.sha256(simulated_data).hexdigest()
        
        return {
            'success': True,
            'file_data': simulated_data,
            'file_path': file_path,
            'file_hash': file_hash,
            'file_size': len(simulated_data),
            'metadata': {'simulated': True},
            'last_modified': datetime.utcnow().isoformat(),
            'simulated': True
        }
    
    def _simulate_delete(self, file_path: str) -> Dict[str, Any]:
        """Simulate file deletion for demo mode"""
        return {
            'success': True,
            'message': f'File deleted (simulated): {file_path}',
            'deleted_at': datetime.utcnow().isoformat(),
            'simulated': True
        }
    
    def _simulate_list(self, prefix: str, limit: int) -> Dict[str, Any]:
        """Simulate file listing for demo mode"""
        simulated_files = [
            {
                'name': f'{prefix}sample_001.encrypted',
                'size': 1024,
                'created': datetime.utcnow().isoformat(),
                'updated': datetime.utcnow().isoformat(),
                'content_type': 'application/octet-stream',
                'metadata': {'sample_id': 'DNA_001', 'encrypted': True}
            },
            {
                'name': f'{prefix}sample_002.encrypted',
                'size': 2048,
                'created': datetime.utcnow().isoformat(),
                'updated': datetime.utcnow().isoformat(),
                'content_type': 'application/octet-stream',
                'metadata': {'sample_id': 'DNA_002', 'encrypted': True}
            }
        ]
        
        return {
            'success': True,
            'files': simulated_files,
            'count': len(simulated_files),
            'prefix': prefix,
            'simulated': True
        }
    
    def _simulate_metadata(self, file_path: str) -> Dict[str, Any]:
        """Simulate metadata retrieval for demo mode"""
        return {
            'success': True,
            'file_path': file_path,
            'size': 1024,
            'content_type': 'application/octet-stream',
            'created': datetime.utcnow().isoformat(),
            'updated': datetime.utcnow().isoformat(),
            'metadata': {'simulated': True},
            'etag': 'simulated-etag-123',
            'simulated': True
        }
    
    def _simulate_upload_url(self, file_path: str, expiration_hours: int) -> Dict[str, Any]:
        """Simulate upload URL generation for demo mode"""
        return {
            'success': True,
            'upload_url': f'https://simulated-storage.com/upload/{file_path}',
            'file_path': file_path,
            'expires_at': (datetime.utcnow() + timedelta(hours=expiration_hours)).isoformat(),
            'method': 'PUT',
            'simulated': True
        }