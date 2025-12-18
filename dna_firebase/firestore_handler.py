"""
Firestore Handler for DNA System Metadata
Manages metadata, user profiles, and system data in Firestore
"""

import os
import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
try:
    import firebase_admin  # type: ignore
    from firebase_admin import credentials, firestore  # type: ignore
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False


class FirestoreHandler:
    """Firestore database handler for metadata and user data"""
    
    def __init__(self, config_path: str = "dna_firebase/config.json"):
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
            if not self.initialized or self.db is None:
                return {'success': False, 'error': 'Firestore not initialized'}
            
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
            if not self.initialized or self.db is None:
                return {'success': False, 'error': 'Firestore not initialized'}
            
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
            if not self.initialized or self.db is None:
                return {'success': False, 'error': 'Firestore not initialized'}
            
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
            if not self.initialized or self.db is None:
                print(f"⚠️  Firestore not initialized")
                return {'success': False, 'error': 'Firestore not initialized'}
            
            print(f"🔥 Storing sample metadata in Firestore: {sample_id}")
            print(f"🔥 Collection: dna_samples, Document: {sample_id}")
            
            # Add timestamps
            metadata.update({
                'created_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            
            # Store in samples collection
            sample_ref = self.db.collection('dna_samples').document(sample_id)
            sample_ref.set(metadata)
            
            print(f"✅ Successfully stored metadata for {sample_id} in Firestore")
            
            return {
                'success': True,
                'sample_id': sample_id,
                'message': 'Sample metadata stored successfully'
            }
            
        except Exception as e:
            print(f"❌ Firestore storage failed for {sample_id}: {str(e)}")
            return {
                'success': False,
                'error': f'Metadata storage failed: {str(e)}'
            }
    
    def store_nft_metadata(self, token_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Store NFT metadata in separate Firestore collection"""
        try:
            if not self.initialized or self.db is None:
                print(f"⚠️  Firestore not initialized")
                return {'success': False, 'error': 'Firestore not initialized'}
            
            print(f"🎨 Storing NFT metadata in Firestore: {token_id}")
            print(f"🎨 Collection: nft_tokens, Document: {token_id}")
            
            # Add timestamps
            metadata.update({
                'created_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            
            # Store in NFT collection (separate from DNA samples)
            nft_ref = self.db.collection('nft_tokens').document(token_id)
            nft_ref.set(metadata)
            
            print(f"✅ Successfully stored NFT metadata for {token_id} in Firestore")
            
            return {
                'success': True,
                'token_id': token_id,
                'message': 'NFT metadata stored successfully'
            }
            
        except Exception as e:
            print(f"❌ NFT Firestore storage failed for {token_id}: {str(e)}")
            return {
                'success': False,
                'error': f'NFT metadata storage failed: {str(e)}'
            }
    
    def query_nfts_by_owner(self, owner_id: str) -> Dict[str, Any]:
        """Query NFT tokens by owner (supports both UID and email lookup)"""
        try:
            if not self.initialized or self.db is None:
                print(f"⚠️  Firestore not initialized")
                return {'success': False, 'error': 'Firestore not initialized'}
            
            print(f"🎨 Querying Firestore for NFTs by owner_uid: {owner_id}")
            nfts_ref = self.db.collection('nft_tokens')
            
            # Query by owner_uid first
            query = nfts_ref.where(filter=firestore.FieldFilter('owner_uid', '==', owner_id))
            docs = list(query.stream())
            
            nfts = []
            for doc in docs:
                nft_data = doc.to_dict()
                nft_data['token_id'] = doc.id
                nfts.append(nft_data)
                print(f"🎨 Found NFT by UID: {doc.id}")
            
            # Also check for legacy transfers that might have stored email instead of UID
            if '@' not in owner_id:  # If owner_id is a UID, also check by email
                # This is a fallback for any NFTs that might have been transferred with email
                # We can't easily get the email from UID here, so we'll skip this for now
                pass
            else:
                # If owner_id is an email, also query by owner field (legacy)
                print(f"🎨 Also querying by email (legacy): {owner_id}")
                email_query = nfts_ref.where(filter=firestore.FieldFilter('owner', '==', owner_id))
                email_docs = list(email_query.stream())
                
                for doc in email_docs:
                    nft_data = doc.to_dict()
                    nft_data['token_id'] = doc.id
                    # Check if we already have this NFT (avoid duplicates)
                    if not any(n['token_id'] == nft_data['token_id'] for n in nfts):
                        nfts.append(nft_data)
                        print(f"🎨 Found NFT by email (legacy): {doc.id}")
            
            print(f"🎨 Firestore NFT query complete: {len(nfts)} NFTs found")
            
            return {
                'success': True,
                'nfts': nfts,
                'count': len(nfts)
            }
            
        except Exception as e:
            print(f"❌ NFT query failed for {owner_id}: {str(e)}")
            return {
                'success': False,
                'error': f'NFT query failed: {str(e)}'
            }
    

    
    def store_access_request(self, request_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store access request in Firestore"""
        try:
            if not self.initialized or self.db is None:
                print(f"⚠️  Firestore not initialized, using simulation for request {request_id}")
                return {'success': True, 'simulated': True}
            
            print(f"🔐 Storing access request in Firestore: {request_id}")
            
            # Add timestamps
            request_data.update({
                'created_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            
            # Store in access_requests collection
            request_ref = self.db.collection('access_requests').document(request_id)
            request_ref.set(request_data)
            
            print(f"✅ Successfully stored access request {request_id} in Firestore")
            
            return {
                'success': True,
                'request_id': request_id,
                'message': 'Access request stored successfully'
            }
            
        except Exception as e:
            print(f"❌ Access request Firestore storage failed for {request_id}: {str(e)}")
            return {
                'success': False,
                'error': f'Access request storage failed: {str(e)}'
            }
    


    def get_sample_metadata(self, sample_id: str) -> Dict[str, Any]:
        """Get DNA sample metadata from Firestore"""
        try:
            if not self.initialized or self.db is None:
                return {'success': False, 'error': 'Firestore not initialized'}
            
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
            if not self.initialized or self.db is None:
                print(f"⚠️  Firestore not initialized")
                return {'success': False, 'error': 'Firestore not initialized'}
            
            print(f"🔥 Querying Firestore for samples by owner_uid: {owner_id}")
            samples_ref = self.db.collection('dna_samples')
            query = samples_ref.where(filter=firestore.FieldFilter('owner_uid', '==', owner_id))
            docs = query.stream()
            
            samples = []
            for doc in docs:
                sample_data = doc.to_dict()
                sample_data['sample_id'] = doc.id
                samples.append(sample_data)
                print(f"📄 Found sample: {doc.id}")
            
            print(f"🔥 Firestore query complete: {len(samples)} samples found")
            
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
    
    # NFT Metadata Management (Fixed - removed duplicates)
    def get_nft_metadata(self, token_id: str) -> Dict[str, Any]:
        """Get NFT metadata from Firestore"""
        try:
            if not self.initialized or self.db is None:
                return {'success': False, 'error': 'Firestore not initialized'}
            
            nft_ref = self.db.collection('nft_tokens').document(token_id)
            nft_doc = nft_ref.get()
            
            if nft_doc.exists:
                return {
                    'success': True,
                    'metadata': nft_doc.to_dict()
                }
            else:
                return {
                    'success': False,
                    'error': 'NFT metadata not found'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'NFT metadata retrieval failed: {str(e)}'
            }
    
    # Access Logs
    def log_access_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Log access event to Firestore"""
        try:
            if not self.initialized or self.db is None:
                return {'success': False, 'error': 'Firestore not initialized'}
            
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
    
    def get_access_logs(self, sample_id: Optional[str] = None, user_id: Optional[str] = None, 
                       limit: int = 100) -> Dict[str, Any]:
        """Get access logs with optional filtering"""
        try:
            if not self.initialized or self.db is None:
                return {'success': False, 'error': 'Firestore not initialized'}
            
            logs_ref = self.db.collection('access_logs')
            query = logs_ref.order_by('timestamp', direction=firestore.Query.DESCENDING)
            
            # Apply filters
            if sample_id:
                query = query.where(filter=firestore.FieldFilter('sample_id', '==', sample_id))
            if user_id:
                query = query.where(filter=firestore.FieldFilter('user_id', '==', user_id))
            
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
            if not self.initialized or self.db is None:
                return {'success': False, 'error': 'Firestore not initialized'}
            
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
            if not self.initialized or self.db is None:
                return {'success': False, 'error': 'Firestore not initialized'}
            
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
            recent_logs = logs_ref.where(filter=firestore.FieldFilter('timestamp', '>=', thirty_days_ago)).stream()
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
    



# Add missing import
import os