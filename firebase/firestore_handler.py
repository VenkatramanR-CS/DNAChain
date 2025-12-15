"""
Firestore Handler for DNA System Metadata
Manages metadata, user profiles, and system data in Firestore
"""

import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False


class FirestoreHandler:
    """Firestore database handler for metadata and user data"""
    
    def __init__(self, config_path: str = "firebase/config.json"):
        self.config_path = config_path
        self.db = None
        self.initialized = False
        
        # Initialize Firestore (with fallback for demo)
        self._initialize_firestore()
    
    def _initialize_firestore(self):
        """Initialize Firestore database"""
        try:
            if not FIREBASE_AVAILABLE:
                print("⚠️  Firebase libraries not available - running in simulation mode")
                self.initialized = False
                return
                
            if not firebase_admin._apps:
                if os.path.exists(self.config_path):
                    cred = credentials.Certificate(self.config_path)
                    firebase_admin.initialize_app(cred)
                else:
                    print("⚠️  Firebase config not found - running in simulation mode")
                    self.initialized = False
                    return
            
            self.db = firestore.client()
            self.initialized = True
            print("✅ Firestore initialized successfully")
            
        except Exception as e:
            print(f"⚠️  Firestore initialization failed: {e}")
            print("📝 Running in simulation mode")
            self.initialized = False
    
    # User Management
    def create_user_profile(self, user_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create user profile in Firestore"""
        try:
            if not self.initialized:
                return self._simulate_user_create(user_id, profile_data)
            
            # Add timestamps
            profile_data.update({
                'created_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP,
                'active': True
            })
            
            # Create user document
            user_ref = self.db.collection('users').document(user_id)
            user_ref.set(profile_data)
            
            return {
                'success': True,
                'user_id': user_id,
                'message': 'User profile created successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'User creation failed: {str(e)}'
            }
    
    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """Get user profile from Firestore"""
        try:
            if not self.initialized:
                return self._simulate_user_get(user_id)
            
            user_ref = self.db.collection('users').document(user_id)
            user_doc = user_ref.get()
            
            if user_doc.exists:
                return {
                    'success': True,
                    'user_data': user_doc.to_dict()
                }
            else:
                return {
                    'success': False,
                    'error': 'User not found'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'User retrieval failed: {str(e)}'
            }
    
    def update_user_profile(self, user_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update user profile in Firestore"""
        try:
            if not self.initialized:
                return self._simulate_user_update(user_id, updates)
            
            # Add update timestamp
            updates['updated_at'] = firestore.SERVER_TIMESTAMP
            
            user_ref = self.db.collection('users').document(user_id)
            user_ref.update(updates)
            
            return {
                'success': True,
                'user_id': user_id,
                'message': 'User profile updated successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'User update failed: {str(e)}'
            }
    
    # DNA Sample Metadata
    def store_sample_metadata(self, sample_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Store DNA sample metadata in Firestore"""
        try:
            if not self.initialized:
                return self._simulate_metadata_store(sample_id, metadata)
            
            # Add timestamps
            metadata.update({
                'created_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            
            # Store in samples collection
            sample_ref = self.db.collection('dna_samples').document(sample_id)
            sample_ref.set(metadata)
            
            return {
                'success': True,
                'sample_id': sample_id,
                'message': 'Sample metadata stored successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Metadata storage failed: {str(e)}'
            }
    
    def get_sample_metadata(self, sample_id: str) -> Dict[str, Any]:
        """Get DNA sample metadata from Firestore"""
        try:
            if not self.initialized:
                return self._simulate_metadata_get(sample_id)
            
            sample_ref = self.db.collection('dna_samples').document(sample_id)
            sample_doc = sample_ref.get()
            
            if sample_doc.exists:
                return {
                    'success': True,
                    'metadata': sample_doc.to_dict()
                }
            else:
                return {
                    'success': False,
                    'error': 'Sample metadata not found'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Metadata retrieval failed: {str(e)}'
            }
    
    def query_samples_by_owner(self, owner_id: str) -> Dict[str, Any]:
        """Query DNA samples by owner"""
        try:
            if not self.initialized:
                return self._simulate_samples_query(owner_id)
            
            samples_ref = self.db.collection('dna_samples')
            query = samples_ref.where('owner', '==', owner_id)
            docs = query.stream()
            
            samples = []
            for doc in docs:
                sample_data = doc.to_dict()
                sample_data['sample_id'] = doc.id
                samples.append(sample_data)
            
            return {
                'success': True,
                'samples': samples,
                'count': len(samples)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Sample query failed: {str(e)}'
            }
    
    # Access Logs
    def log_access_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Log access event to Firestore"""
        try:
            if not self.initialized:
                return self._simulate_access_log(event_data)
            
            # Add timestamp
            event_data['timestamp'] = firestore.SERVER_TIMESTAMP
            event_data['event_id'] = f"access_{int(time.time() * 1000)}"
            
            # Store in access_logs collection
            log_ref = self.db.collection('access_logs').document()
            log_ref.set(event_data)
            
            return {
                'success': True,
                'event_id': event_data['event_id'],
                'message': 'Access event logged successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Access logging failed: {str(e)}'
            }
    
    def get_access_logs(self, sample_id: str = None, user_id: str = None, 
                       limit: int = 100) -> Dict[str, Any]:
        """Get access logs with optional filtering"""
        try:
            if not self.initialized:
                return self._simulate_access_logs_get(sample_id, user_id, limit)
            
            logs_ref = self.db.collection('access_logs')
            query = logs_ref.order_by('timestamp', direction=firestore.Query.DESCENDING)
            
            # Apply filters
            if sample_id:
                query = query.where('sample_id', '==', sample_id)
            if user_id:
                query = query.where('user_id', '==', user_id)
            
            # Apply limit
            query = query.limit(limit)
            
            docs = query.stream()
            logs = []
            for doc in docs:
                log_data = doc.to_dict()
                log_data['log_id'] = doc.id
                logs.append(log_data)
            
            return {
                'success': True,
                'logs': logs,
                'count': len(logs)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Access logs retrieval failed: {str(e)}'
            }
    
    # System Analytics
    def store_analytics_event(self, event_type: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store analytics event"""
        try:
            if not self.initialized:
                return self._simulate_analytics_store(event_type, event_data)
            
            # Prepare analytics document
            analytics_data = {
                'event_type': event_type,
                'event_data': event_data,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'date': datetime.utcnow().strftime('%Y-%m-%d')
            }
            
            # Store in analytics collection
            analytics_ref = self.db.collection('analytics').document()
            analytics_ref.set(analytics_data)
            
            return {
                'success': True,
                'message': 'Analytics event stored successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Analytics storage failed: {str(e)}'
            }
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        try:
            if not self.initialized:
                return self._simulate_system_stats()
            
            stats = {}
            
            # Count users
            users_ref = self.db.collection('users')
            users_count = len(list(users_ref.stream()))
            stats['total_users'] = users_count
            
            # Count DNA samples
            samples_ref = self.db.collection('dna_samples')
            samples_count = len(list(samples_ref.stream()))
            stats['total_samples'] = samples_count
            
            # Count access logs (last 30 days)
            thirty_days_ago = datetime.utcnow().timestamp() - (30 * 24 * 3600)
            logs_ref = self.db.collection('access_logs')
            recent_logs = logs_ref.where('timestamp', '>=', thirty_days_ago).stream()
            stats['recent_access_events'] = len(list(recent_logs))
            
            return {
                'success': True,
                'stats': stats,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Stats retrieval failed: {str(e)}'
            }
    
    # Simulation methods for demo mode
    def _simulate_user_create(self, user_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'success': True,
            'user_id': user_id,
            'message': 'User profile created successfully (simulated)',
            'simulated': True
        }
    
    def _simulate_user_get(self, user_id: str) -> Dict[str, Any]:
        return {
            'success': True,
            'user_data': {
                'user_id': user_id,
                'name': f'User {user_id}',
                'email': f'{user_id}@example.com',
                'role': 'researcher',
                'created_at': datetime.utcnow().isoformat(),
                'active': True,
                'simulated': True
            },
            'simulated': True
        }
    
    def _simulate_user_update(self, user_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'success': True,
            'user_id': user_id,
            'message': 'User profile updated successfully (simulated)',
            'simulated': True
        }
    
    def _simulate_metadata_store(self, sample_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'success': True,
            'sample_id': sample_id,
            'message': 'Sample metadata stored successfully (simulated)',
            'simulated': True
        }
    
    def _simulate_metadata_get(self, sample_id: str) -> Dict[str, Any]:
        return {
            'success': True,
            'metadata': {
                'sample_id': sample_id,
                'type': 'saliva',
                'collection_date': '2024-12-15',
                'patient_id': 'PATIENT_001',
                'encrypted': True,
                'file_path': f'samples/{sample_id}.encrypted',
                'created_at': datetime.utcnow().isoformat(),
                'simulated': True
            },
            'simulated': True
        }
    
    def _simulate_samples_query(self, owner_id: str) -> Dict[str, Any]:
        return {
            'success': True,
            'samples': [
                {
                    'sample_id': 'DNA_001',
                    'owner': owner_id,
                    'type': 'saliva',
                    'created_at': datetime.utcnow().isoformat(),
                    'simulated': True
                },
                {
                    'sample_id': 'DNA_002',
                    'owner': owner_id,
                    'type': 'blood',
                    'created_at': datetime.utcnow().isoformat(),
                    'simulated': True
                }
            ],
            'count': 2,
            'simulated': True
        }
    
    def _simulate_access_log(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'success': True,
            'event_id': f"access_{int(time.time() * 1000)}",
            'message': 'Access event logged successfully (simulated)',
            'simulated': True
        }
    
    def _simulate_access_logs_get(self, sample_id: str, user_id: str, limit: int) -> Dict[str, Any]:
        return {
            'success': True,
            'logs': [
                {
                    'log_id': 'log_001',
                    'event_type': 'access_granted',
                    'sample_id': sample_id or 'DNA_001',
                    'user_id': user_id or 'researcher_001',
                    'timestamp': datetime.utcnow().isoformat(),
                    'simulated': True
                }
            ],
            'count': 1,
            'simulated': True
        }
    
    def _simulate_analytics_store(self, event_type: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'success': True,
            'message': 'Analytics event stored successfully (simulated)',
            'simulated': True
        }
    
    def _simulate_system_stats(self) -> Dict[str, Any]:
        return {
            'success': True,
            'stats': {
                'total_users': 25,
                'total_samples': 150,
                'recent_access_events': 45,
                'simulated': True
            },
            'generated_at': datetime.utcnow().isoformat(),
            'simulated': True
        }


# Add missing import
import os