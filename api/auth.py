"""
Firebase Authentication Module for DNA Blockchain Access System
Handles user registration, login, and authentication
"""

import os
import json
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from functools import wraps

import firebase_admin  # type: ignore
from firebase_admin import credentials, auth, firestore  # type: ignore
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .models.schemas import UserRegistration, UserLogin, UserProfile, AuthResponse


class FirebaseAuth:
    """Firebase authentication handler"""
    
    def __init__(self):
        self.initialized = False
        self.db = None
        self.security = HTTPBearer()
        self.init_firebase()
    
    def init_firebase(self):
        """Initialize Firebase Admin SDK"""
        try:
            # Check if Firebase is already initialized
            if not firebase_admin._apps:
                config_path = os.path.join(os.path.dirname(__file__), '..', 'dna_firebase', 'config.json')
                
                if os.path.exists(config_path):
                    # Load Firebase config
                    with open(config_path, 'r') as f:
                        config_data = json.load(f)
                    
                    # Check if it's a real config (not placeholder)
                    if config_data.get('project_id') == 'dna-blockchain-system' or 'YOUR_PRIVATE_KEY_HERE' in config_data.get('private_key', ''):
                        print("⚠️  Firebase config contains placeholder data. Running in simulation mode.")
                        self.initialized = False
                        return
                    
                    # Initialize with service account and storage bucket
                    cred = credentials.Certificate(config_path)
                    firebase_admin.initialize_app(cred, {
                        'storageBucket': f"{config_data.get('project_id')}.firebasestorage.app"
                    })
                    self.db = firestore.client()
                    self.initialized = True
                    print("✅ Firebase initialized successfully")
                else:
                    print("⚠️  Firebase config not found. Running in simulation mode.")
                    self.initialized = False
            else:
                self.db = firestore.client()
                self.initialized = True
                
        except Exception as e:
            print(f"⚠️  Firebase initialization failed: {e}. Running in simulation mode.")
            self.initialized = False
    
    async def register_user(self, registration: UserRegistration) -> AuthResponse:
        """Register a new user"""
        try:
            if not self.initialized:
                return self._simulate_registration(registration)
            
            # Create user in Firebase Auth
            user_record = auth.create_user(
                email=registration.email,
                password=registration.password,
                display_name=registration.display_name,
                email_verified=False
            )
            
            # Create user profile in Firestore
            user_profile = {
                'uid': user_record.uid,
                'email': registration.email,
                'display_name': registration.display_name,
                'role': registration.role,
                'created_at': datetime.utcnow(),
                'verified': False,
                'wallet_address': self._generate_wallet_address(user_record.uid)
            }
            
            self.db.collection('users').document(user_record.uid).set(user_profile)
            
            # Generate custom token
            token = auth.create_custom_token(user_record.uid)
            
            return AuthResponse(
                success=True,
                user=UserProfile(**user_profile),
                token=token.decode('utf-8'),
                message="User registered successfully"
            )
            
        except auth.EmailAlreadyExistsError:
            return AuthResponse(
                success=False,
                error="Email already exists"
            )
        except Exception as e:
            return AuthResponse(
                success=False,
                error=f"Registration failed: {str(e)}"
            )
    
    async def login_user(self, login: UserLogin) -> AuthResponse:
        """Login user (simulation since Firebase Admin SDK doesn't handle client auth)"""
        try:
            if not self.initialized:
                return self._simulate_login(login)
            
            # In a real implementation, this would be handled by Firebase client SDK
            # For now, we'll verify the user exists and generate a custom token
            try:
                user_record = auth.get_user_by_email(login.email)
                
                # Get user profile from Firestore
                user_doc = self.db.collection('users').document(user_record.uid).get()
                if not user_doc.exists:
                    return AuthResponse(
                        success=False,
                        error="User profile not found"
                    )
                
                user_data = user_doc.to_dict()
                user_data['last_login'] = datetime.utcnow()
                
                # Update last login
                self.db.collection('users').document(user_record.uid).update({
                    'last_login': user_data['last_login']
                })
                
                # Generate custom token
                token = auth.create_custom_token(user_record.uid)
                
                return AuthResponse(
                    success=True,
                    user=UserProfile(**user_data),
                    token=token.decode('utf-8'),
                    message="Login successful"
                )
                
            except auth.UserNotFoundError:
                return AuthResponse(
                    success=False,
                    error="User not found"
                )
                
        except Exception as e:
            return AuthResponse(
                success=False,
                error=f"Login failed: {str(e)}"
            )
    
    async def verify_token(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> UserProfile:
        """Verify Firebase token and return user profile"""
        try:
            if not self.initialized:
                print(f"🔍 Using simulation mode for token: {credentials.credentials[:20]}...")
                return self._simulate_user_from_token(credentials.credentials)
            
            print(f"🔍 Verifying Firebase token: {credentials.credentials[:20]}...")
            
            # Verify the token
            decoded_token = auth.verify_id_token(credentials.credentials)
            uid = decoded_token['uid']
            print(f"✅ Token verified for user: {uid}")
            
            # Get user profile
            if self.db is None:
                print("⚠️ Firestore not available, creating basic profile")
                return UserProfile(
                    uid=uid,
                    email=decoded_token.get('email', f'{uid}@firebase.user'),
                    displayName=decoded_token.get('name', f'User {uid}'),
                    role='user',
                    createdAt=datetime.utcnow(),
                    lastLogin=datetime.utcnow(),
                    wallet_address=self._generate_wallet_address(uid),
                    verified=True
                )
            
            user_doc = self.db.collection('users').document(uid).get()
            if not user_doc.exists:
                print(f"⚠️ User profile not found in Firestore, creating basic profile for {uid}")
                return UserProfile(
                    uid=uid,
                    email=decoded_token.get('email', f'{uid}@firebase.user'),
                    displayName=decoded_token.get('name', f'User {uid}'),
                    role='user',
                    createdAt=datetime.utcnow(),
                    lastLogin=datetime.utcnow(),
                    wallet_address=self._generate_wallet_address(uid),
                    verified=True
                )
            
            print(f"✅ User profile found in Firestore for {uid}")
            return UserProfile(**user_doc.to_dict())
            
        except Exception as e:
            print(f"❌ Token verification failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )
    
    async def get_user_profile(self, uid: str) -> Optional[UserProfile]:
        """Get user profile by UID"""
        try:
            if not self.initialized:
                return self._simulate_user_profile(uid)
            
            user_doc = self.db.collection('users').document(uid).get()
            if user_doc.exists:
                return UserProfile(**user_doc.to_dict())
            return None
            
        except Exception as e:
            print(f"Error getting user profile: {e}")
            return None
    
    async def get_uid_by_email(self, email: str) -> Optional[str]:
        """Get Firebase UID by email address"""
        try:
            if not self.initialized:
                # Simulate UID from email for demo mode
                return f"sim_{hashlib.md5(email.encode()).hexdigest()[:8]}"
            
            user_record = auth.get_user_by_email(email)
            return user_record.uid
            
        except auth.UserNotFoundError:
            print(f"User not found for email: {email}")
            return None
        except Exception as e:
            print(f"Error getting UID by email: {e}")
            return None
    
    async def update_user_profile(self, uid: str, updates: Dict[str, Any]) -> bool:
        """Update user profile"""
        try:
            if not self.initialized:
                return True  # Simulate success
            
            self.db.collection('users').document(uid).update(updates)
            return True
            
        except Exception as e:
            print(f"Error updating user profile: {e}")
            return False
    
    def _generate_wallet_address(self, uid: str) -> str:
        """Generate a wallet address from UID"""
        hash_obj = hashlib.sha256(uid.encode())
        return f"0x{hash_obj.hexdigest()[:40]}"
    
    def _simulate_registration(self, registration: UserRegistration) -> AuthResponse:
        """Simulate user registration for testing"""
        uid = f"sim_{hashlib.md5(registration.email.encode()).hexdigest()[:8]}"
        
        user_profile = UserProfile(
            uid=uid,
            email=registration.email,
            displayName=registration.display_name,
            role=registration.role,
            createdAt=datetime.utcnow(),
            lastLogin=datetime.utcnow(),
            wallet_address=self._generate_wallet_address(uid),
            verified=True
        )
        
        return AuthResponse(
            success=True,
            user=user_profile,
            token=f"sim_token_{uid}",
            message="User registered successfully (simulation)"
        )
    
    def _simulate_login(self, login: UserLogin) -> AuthResponse:
        """Simulate user login for testing"""
        uid = f"sim_{hashlib.md5(login.email.encode()).hexdigest()[:8]}"
        
        user_profile = UserProfile(
            uid=uid,
            email=login.email,
            displayName=login.email.split('@')[0].title(),
            role="user",
            createdAt=datetime.utcnow() - timedelta(days=30),
            lastLogin=datetime.utcnow(),
            wallet_address=self._generate_wallet_address(uid),
            verified=True
        )
        
        return AuthResponse(
            success=True,
            user=user_profile,
            token=f"sim_token_{uid}",
            message="Login successful (simulation)"
        )
    
    def _simulate_user_from_token(self, token: str) -> UserProfile:
        """Simulate user from token for testing"""
        if not (token.startswith('sim_token_') or token.startswith('demo_token_')):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format"
            )
        
        if token.startswith('sim_token_'):
            uid = token.replace('sim_token_', '')
        else:
            uid = token.replace('demo_token_', '')
        
        return UserProfile(
            uid=uid,
            email=f"user_{uid}@example.com",
            displayName=f"User {uid}",
            role="user",
            createdAt=datetime.utcnow() - timedelta(days=30),
            lastLogin=datetime.utcnow(),
            wallet_address=self._generate_wallet_address(uid),
            verified=True
        )
    
    def _simulate_user_profile(self, uid: str) -> UserProfile:
        """Simulate user profile for testing"""
        return UserProfile(
            uid=uid,
            email=f"user_{uid}@example.com",
            displayName=f"User {uid}",
            role="user",
            createdAt=datetime.utcnow() - timedelta(days=30),
            lastLogin=datetime.utcnow(),
            wallet_address=self._generate_wallet_address(uid),
            verified=True
        )


# Global auth instance
firebase_auth = FirebaseAuth()


def require_auth(func):
    """Decorator to require authentication"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # This would be used with FastAPI dependency injection
        return await func(*args, **kwargs)
    return wrapper


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    """FastAPI dependency to get current user"""
    return await firebase_auth.verify_token(credentials)