"""
Access Control Module
Manages access requests and permissions for DNA samples
"""

import time
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum


class AccessStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    REVOKED = "revoked"


class UserRole(Enum):
    ADMIN = "admin"
    MODERATOR = "moderator"
    REQUESTER = "requester"


@dataclass
class AccessRequest:
    """Access request data structure"""
    request_id: str
    requester: str
    sample_id: str
    purpose: str
    status: AccessStatus
    created_at: int
    updated_at: int
    approvals: List[str]  # List of approver addresses
    required_approvals: int = 2  # Default 2-of-3 multisig
    expiry_time: Optional[int] = None
    metadata: Dict[str, Any] = None


@dataclass
class UserPermission:
    """User permission data structure"""
    address: str
    role: UserRole
    granted_by: str
    granted_at: int
    active: bool = True


class AccessControl:
    """Access control and permission management"""
    
    def __init__(self):
        self.access_requests: Dict[str, AccessRequest] = {}
        self.user_permissions: Dict[str, UserPermission] = {}
        self.sample_permissions: Dict[str, List[str]] = {}  # sample_id -> [authorized_addresses]
        
        # Initialize with default admin (for testing)
        self._init_default_permissions()
    
    def _init_default_permissions(self):
        """Initialize default admin permissions"""
        # This would be configured during genesis in production
        default_admin = "admin_address_placeholder"
        self.user_permissions[default_admin] = UserPermission(
            address=default_admin,
            role=UserRole.ADMIN,
            granted_by="genesis",
            granted_at=int(time.time())
        )
    
    def request_access(self, requester: str, sample_id: str, 
                      purpose: str, expiry_hours: int = 24) -> Dict[str, Any]:
        """Submit an access request for a DNA sample"""
        try:
            # Validate inputs
            if not requester or not sample_id or not purpose:
                return {
                    'success': False,
                    'message': 'Missing required fields'
                }
            
            # Check if user has permission to request
            if not self._can_request_access(requester):
                return {
                    'success': False,
                    'message': 'User not authorized to request access'
                }
            
            # Generate request ID
            request_id = str(uuid.uuid4())
            
            # Calculate expiry time
            expiry_time = int(time.time()) + (expiry_hours * 3600)
            
            # Create access request
            request = AccessRequest(
                request_id=request_id,
                requester=requester,
                sample_id=sample_id,
                purpose=purpose,
                status=AccessStatus.PENDING,
                created_at=int(time.time()),
                updated_at=int(time.time()),
                approvals=[],
                expiry_time=expiry_time,
                metadata={}
            )
            
            # Store request
            self.access_requests[request_id] = request
            
            # Create event
            event = {
                'type': 'access_requested',
                'attributes': {
                    'request_id': request_id,
                    'requester': requester,
                    'sample_id': sample_id,
                    'purpose': purpose,
                    'expiry_time': str(expiry_time),
                    'timestamp': str(request.created_at)
                }
            }
            
            return {
                'success': True,
                'message': f'Access request {request_id} submitted',
                'events': [event],
                'data': {
                    'request_id': request_id,
                    'status': request.status.value,
                    'expiry_time': expiry_time
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Access request failed: {str(e)}'
            }
    
    def approve_access(self, approver: str, request_id: str) -> Dict[str, Any]:
        """Approve an access request (part of multisig process)"""
        try:
            request = self.access_requests.get(request_id)
            if not request:
                return {
                    'success': False,
                    'message': f'Request {request_id} not found'
                }
            
            # Check if approver has permission
            if not self._can_approve_access(approver):
                return {
                    'success': False,
                    'message': 'User not authorized to approve access'
                }
            
            # Check if request is still pending
            if request.status != AccessStatus.PENDING:
                return {
                    'success': False,
                    'message': f'Request is {request.status.value}, cannot approve'
                }
            
            # Check if request has expired
            if request.expiry_time and int(time.time()) > request.expiry_time:
                request.status = AccessStatus.DENIED
                return {
                    'success': False,
                    'message': 'Request has expired'
                }
            
            # Check if already approved by this user
            if approver in request.approvals:
                return {
                    'success': False,
                    'message': 'Already approved by this user'
                }
            
            # Add approval
            request.approvals.append(approver)
            request.updated_at = int(time.time())
            
            # Check if enough approvals
            if len(request.approvals) >= request.required_approvals:
                request.status = AccessStatus.APPROVED
                
                # Grant access to sample
                if request.sample_id not in self.sample_permissions:
                    self.sample_permissions[request.sample_id] = []
                
                if request.requester not in self.sample_permissions[request.sample_id]:
                    self.sample_permissions[request.sample_id].append(request.requester)
            
            # Create event
            event_type = 'access_approved' if request.status == AccessStatus.APPROVED else 'access_approval_added'
            event = {
                'type': event_type,
                'attributes': {
                    'request_id': request_id,
                    'approver': approver,
                    'requester': request.requester,
                    'sample_id': request.sample_id,
                    'approvals_count': str(len(request.approvals)),
                    'required_approvals': str(request.required_approvals),
                    'status': request.status.value,
                    'timestamp': str(request.updated_at)
                }
            }
            
            return {
                'success': True,
                'message': f'Approval added to request {request_id}',
                'events': [event],
                'data': {
                    'request_id': request_id,
                    'status': request.status.value,
                    'approvals_count': len(request.approvals),
                    'required_approvals': request.required_approvals
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Approval failed: {str(e)}'
            }
    
    def deny_access(self, denier: str, request_id: str, 
                   reason: str = "") -> Dict[str, Any]:
        """Deny an access request"""
        try:
            request = self.access_requests.get(request_id)
            if not request:
                return {
                    'success': False,
                    'message': f'Request {request_id} not found'
                }
            
            # Check if denier has permission
            if not self._can_approve_access(denier):
                return {
                    'success': False,
                    'message': 'User not authorized to deny access'
                }
            
            # Check if request is still pending
            if request.status != AccessStatus.PENDING:
                return {
                    'success': False,
                    'message': f'Request is {request.status.value}, cannot deny'
                }
            
            # Deny request
            request.status = AccessStatus.DENIED
            request.updated_at = int(time.time())
            if reason:
                request.metadata['denial_reason'] = reason
            
            # Create event
            event = {
                'type': 'access_denied',
                'attributes': {
                    'request_id': request_id,
                    'denier': denier,
                    'requester': request.requester,
                    'sample_id': request.sample_id,
                    'reason': reason,
                    'timestamp': str(request.updated_at)
                }
            }
            
            return {
                'success': True,
                'message': f'Request {request_id} denied',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Denial failed: {str(e)}'
            }
    
    def revoke_access(self, revoker: str, sample_id: str, 
                     user_address: str) -> Dict[str, Any]:
        """Revoke access to a sample"""
        try:
            # Check if revoker has permission
            if not self._can_approve_access(revoker):
                return {
                    'success': False,
                    'message': 'User not authorized to revoke access'
                }
            
            # Remove from sample permissions
            if sample_id in self.sample_permissions:
                if user_address in self.sample_permissions[sample_id]:
                    self.sample_permissions[sample_id].remove(user_address)
            
            # Create event
            event = {
                'type': 'access_revoked',
                'attributes': {
                    'revoker': revoker,
                    'user_address': user_address,
                    'sample_id': sample_id,
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Access revoked for {user_address} to sample {sample_id}',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Revocation failed: {str(e)}'
            }
    
    def grant_user_permission(self, granter: str, user_address: str, 
                            role: str) -> Dict[str, Any]:
        """Grant user permission/role"""
        try:
            # Check if granter is admin
            granter_perm = self.user_permissions.get(granter)
            if not granter_perm or granter_perm.role != UserRole.ADMIN:
                return {
                    'success': False,
                    'message': 'Only admins can grant permissions'
                }
            
            # Validate role
            try:
                user_role = UserRole(role)
            except ValueError:
                return {
                    'success': False,
                    'message': f'Invalid role: {role}'
                }
            
            # Grant permission
            permission = UserPermission(
                address=user_address,
                role=user_role,
                granted_by=granter,
                granted_at=int(time.time())
            )
            
            self.user_permissions[user_address] = permission
            
            # Create event
            event = {
                'type': 'permission_granted',
                'attributes': {
                    'granter': granter,
                    'user_address': user_address,
                    'role': role,
                    'timestamp': str(permission.granted_at)
                }
            }
            
            return {
                'success': True,
                'message': f'Permission granted to {user_address}',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Permission grant failed: {str(e)}'
            }
    
    def check_access_permission(self, user_address: str, 
                              sample_id: str) -> bool:
        """Check if user has access to sample"""
        # Check direct sample permissions
        sample_perms = self.sample_permissions.get(sample_id, [])
        if user_address in sample_perms:
            return True
        
        # Check if user is admin or moderator
        user_perm = self.user_permissions.get(user_address)
        if user_perm and user_perm.active:
            if user_perm.role in [UserRole.ADMIN, UserRole.MODERATOR]:
                return True
        
        return False
    
    def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get access request by ID"""
        request = self.access_requests.get(request_id)
        if request:
            result = asdict(request)
            result['status'] = request.status.value
            return result
        return None
    
    def get_requests_by_user(self, user_address: str) -> List[Dict[str, Any]]:
        """Get all requests by user"""
        results = []
        for request in self.access_requests.values():
            if request.requester == user_address:
                result = asdict(request)
                result['status'] = request.status.value
                results.append(result)
        return results
    
    def get_pending_requests(self) -> List[Dict[str, Any]]:
        """Get all pending requests"""
        results = []
        for request in self.access_requests.values():
            if request.status == AccessStatus.PENDING:
                result = asdict(request)
                result['status'] = request.status.value
                results.append(result)
        return results
    
    def _can_request_access(self, user_address: str) -> bool:
        """Check if user can request access"""
        # For now, anyone can request access
        # In production, you might want to restrict this
        return True
    
    def _can_approve_access(self, user_address: str) -> bool:
        """Check if user can approve access requests"""
        user_perm = self.user_permissions.get(user_address)
        if user_perm and user_perm.active:
            return user_perm.role in [UserRole.ADMIN, UserRole.MODERATOR]
        return False
    
    def get_permissions(self, user_address: str) -> Optional[Dict[str, Any]]:
        """Get user permissions"""
        perm = self.user_permissions.get(user_address)
        if perm:
            result = asdict(perm)
            result['role'] = perm.role.value
            return result
        return None
    
    def get_all_requests(self) -> Dict[str, Dict[str, Any]]:
        """Get all requests (for state hash calculation)"""
        results = {}
        for rid, request in self.access_requests.items():
            result = asdict(request)
            result['status'] = request.status.value
            results[rid] = result
        return results