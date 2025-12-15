"""
Multi-Signature Module
Implements 2-of-3 threshold signature logic for access approvals
"""

import time
import hashlib
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, asdict
from enum import Enum


class ProposalStatus(Enum):
    PENDING = "pending"
    EXECUTED = "executed"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ProposalType(Enum):
    ACCESS_APPROVAL = "access_approval"
    PERMISSION_GRANT = "permission_grant"
    SYSTEM_UPDATE = "system_update"


@dataclass
class MultiSigProposal:
    """Multi-signature proposal data structure"""
    proposal_id: str
    proposer: str
    proposal_type: ProposalType
    target_data: Dict[str, Any]  # The data/action being proposed
    required_signatures: int
    signatures: List[str]  # List of signer addresses
    status: ProposalStatus
    created_at: int
    expiry_time: int
    executed_at: Optional[int] = None
    execution_result: Optional[Dict[str, Any]] = None


class MultiSig:
    """Multi-signature implementation for critical operations"""
    
    def __init__(self):
        self.proposals: Dict[str, MultiSigProposal] = {}
        self.authorized_signers: Set[str] = set()
        self.default_threshold = 2  # 2-of-3 by default
        
        # Initialize with default signers (would be set in genesis)
        self._init_default_signers()
    
    def _init_default_signers(self):
        """Initialize default authorized signers"""
        # These would be configured during genesis in production
        default_signers = [
            "signer1_address_placeholder",
            "signer2_address_placeholder", 
            "signer3_address_placeholder"
        ]
        self.authorized_signers.update(default_signers)
    
    def create_proposal(self, proposer: str, proposal_type: str, 
                       target_data: Dict[str, Any], 
                       required_signatures: int = None) -> Dict[str, Any]:
        """Create a new multi-sig proposal"""
        try:
            # Validate proposer
            if proposer not in self.authorized_signers:
                return {
                    'success': False,
                    'message': 'Proposer not authorized'
                }
            
            # Validate proposal type
            try:
                prop_type = ProposalType(proposal_type)
            except ValueError:
                return {
                    'success': False,
                    'message': f'Invalid proposal type: {proposal_type}'
                }
            
            # Generate proposal ID
            proposal_id = hashlib.sha256(
                f"{proposer}{proposal_type}{time.time()}".encode()
            ).hexdigest()[:16]
            
            # Set required signatures
            if required_signatures is None:
                required_signatures = self.default_threshold
            
            # Create proposal
            proposal = MultiSigProposal(
                proposal_id=proposal_id,
                proposer=proposer,
                proposal_type=prop_type,
                target_data=target_data,
                required_signatures=required_signatures,
                signatures=[proposer],  # Proposer automatically signs
                status=ProposalStatus.PENDING,
                created_at=int(time.time()),
                expiry_time=int(time.time()) + (24 * 3600)  # 24 hours
            )
            
            # Store proposal
            self.proposals[proposal_id] = proposal
            
            # Create event
            event = {
                'type': 'multisig_proposal_created',
                'attributes': {
                    'proposal_id': proposal_id,
                    'proposer': proposer,
                    'proposal_type': proposal_type,
                    'required_signatures': str(required_signatures),
                    'expiry_time': str(proposal.expiry_time),
                    'timestamp': str(proposal.created_at)
                }
            }
            
            return {
                'success': True,
                'message': f'Proposal {proposal_id} created',
                'events': [event],
                'data': {
                    'proposal_id': proposal_id,
                    'required_signatures': required_signatures,
                    'current_signatures': 1
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Proposal creation failed: {str(e)}'
            }
    
    def sign_proposal(self, signer: str, proposal_id: str) -> Dict[str, Any]:
        """Sign a multi-sig proposal"""
        try:
            proposal = self.proposals.get(proposal_id)
            if not proposal:
                return {
                    'success': False,
                    'message': f'Proposal {proposal_id} not found'
                }
            
            # Validate signer
            if signer not in self.authorized_signers:
                return {
                    'success': False,
                    'message': 'Signer not authorized'
                }
            
            # Check if proposal is still pending
            if proposal.status != ProposalStatus.PENDING:
                return {
                    'success': False,
                    'message': f'Proposal is {proposal.status.value}, cannot sign'
                }
            
            # Check if proposal has expired
            if int(time.time()) > proposal.expiry_time:
                proposal.status = ProposalStatus.EXPIRED
                return {
                    'success': False,
                    'message': 'Proposal has expired'
                }
            
            # Check if already signed
            if signer in proposal.signatures:
                return {
                    'success': False,
                    'message': 'Already signed by this signer'
                }
            
            # Add signature
            proposal.signatures.append(signer)
            
            # Check if enough signatures to execute
            if len(proposal.signatures) >= proposal.required_signatures:
                execution_result = self._execute_proposal(proposal)
                proposal.status = ProposalStatus.EXECUTED if execution_result['success'] else ProposalStatus.REJECTED
                proposal.executed_at = int(time.time())
                proposal.execution_result = execution_result
            
            # Create event
            event_type = 'multisig_proposal_executed' if proposal.status == ProposalStatus.EXECUTED else 'multisig_proposal_signed'
            event = {
                'type': event_type,
                'attributes': {
                    'proposal_id': proposal_id,
                    'signer': signer,
                    'signatures_count': str(len(proposal.signatures)),
                    'required_signatures': str(proposal.required_signatures),
                    'status': proposal.status.value,
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Proposal {proposal_id} signed',
                'events': [event],
                'data': {
                    'proposal_id': proposal_id,
                    'status': proposal.status.value,
                    'signatures_count': len(proposal.signatures),
                    'execution_result': proposal.execution_result
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Signing failed: {str(e)}'
            }
    
    def _execute_proposal(self, proposal: MultiSigProposal) -> Dict[str, Any]:
        """Execute a proposal that has enough signatures"""
        try:
            if proposal.proposal_type == ProposalType.ACCESS_APPROVAL:
                return self._execute_access_approval(proposal.target_data)
            elif proposal.proposal_type == ProposalType.PERMISSION_GRANT:
                return self._execute_permission_grant(proposal.target_data)
            elif proposal.proposal_type == ProposalType.SYSTEM_UPDATE:
                return self._execute_system_update(proposal.target_data)
            else:
                return {
                    'success': False,
                    'message': f'Unknown proposal type: {proposal.proposal_type}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': f'Execution failed: {str(e)}'
            }
    
    def _execute_access_approval(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute access approval proposal"""
        # This would integrate with the access control module
        return {
            'success': True,
            'message': 'Access approval executed',
            'data': target_data
        }
    
    def _execute_permission_grant(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute permission grant proposal"""
        # This would integrate with the access control module
        return {
            'success': True,
            'message': 'Permission grant executed',
            'data': target_data
        }
    
    def _execute_system_update(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute system update proposal"""
        # This would handle system configuration updates
        return {
            'success': True,
            'message': 'System update executed',
            'data': target_data
        }
    
    def approve_access(self, approver: str, request_id: str, 
                      signature: str) -> Dict[str, Any]:
        """Approve access request (called from ABCI app)"""
        try:
            # Validate approver
            if approver not in self.authorized_signers:
                return {
                    'success': False,
                    'message': 'Approver not authorized'
                }
            
            # Create proposal for access approval
            target_data = {
                'request_id': request_id,
                'approver': approver,
                'signature': signature
            }
            
            return self.create_proposal(
                proposer=approver,
                proposal_type='access_approval',
                target_data=target_data
            )
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Access approval failed: {str(e)}'
            }
    
    def add_signer(self, admin: str, new_signer: str) -> Dict[str, Any]:
        """Add new authorized signer (admin only)"""
        try:
            # In production, this would check admin permissions
            if admin not in self.authorized_signers:
                return {
                    'success': False,
                    'message': 'Only authorized signers can add new signers'
                }
            
            if new_signer in self.authorized_signers:
                return {
                    'success': False,
                    'message': 'Signer already authorized'
                }
            
            self.authorized_signers.add(new_signer)
            
            # Create event
            event = {
                'type': 'signer_added',
                'attributes': {
                    'admin': admin,
                    'new_signer': new_signer,
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Signer {new_signer} added',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Add signer failed: {str(e)}'
            }
    
    def remove_signer(self, admin: str, signer_to_remove: str) -> Dict[str, Any]:
        """Remove authorized signer (admin only)"""
        try:
            if admin not in self.authorized_signers:
                return {
                    'success': False,
                    'message': 'Only authorized signers can remove signers'
                }
            
            if signer_to_remove not in self.authorized_signers:
                return {
                    'success': False,
                    'message': 'Signer not found'
                }
            
            # Ensure we don't go below minimum signers
            if len(self.authorized_signers) <= self.default_threshold:
                return {
                    'success': False,
                    'message': 'Cannot remove signer: would go below minimum threshold'
                }
            
            self.authorized_signers.remove(signer_to_remove)
            
            # Create event
            event = {
                'type': 'signer_removed',
                'attributes': {
                    'admin': admin,
                    'removed_signer': signer_to_remove,
                    'timestamp': str(int(time.time()))
                }
            }
            
            return {
                'success': True,
                'message': f'Signer {signer_to_remove} removed',
                'events': [event]
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Remove signer failed: {str(e)}'
            }
    
    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        """Get proposal by ID"""
        proposal = self.proposals.get(proposal_id)
        if proposal:
            result = asdict(proposal)
            result['status'] = proposal.status.value
            result['proposal_type'] = proposal.proposal_type.value
            return result
        return None
    
    def get_pending_proposals(self) -> List[Dict[str, Any]]:
        """Get all pending proposals"""
        results = []
        current_time = int(time.time())
        
        for proposal in self.proposals.values():
            # Check for expired proposals
            if proposal.status == ProposalStatus.PENDING and current_time > proposal.expiry_time:
                proposal.status = ProposalStatus.EXPIRED
            
            if proposal.status == ProposalStatus.PENDING:
                result = asdict(proposal)
                result['status'] = proposal.status.value
                result['proposal_type'] = proposal.proposal_type.value
                results.append(result)
        
        return results
    
    def get_proposals_by_signer(self, signer: str) -> List[Dict[str, Any]]:
        """Get proposals that can be signed by signer"""
        results = []
        
        for proposal in self.proposals.values():
            if (proposal.status == ProposalStatus.PENDING and 
                signer in self.authorized_signers and 
                signer not in proposal.signatures):
                result = asdict(proposal)
                result['status'] = proposal.status.value
                result['proposal_type'] = proposal.proposal_type.value
                results.append(result)
        
        return results
    
    def get_authorized_signers(self) -> List[str]:
        """Get list of authorized signers"""
        return list(self.authorized_signers)
    
    def is_authorized_signer(self, address: str) -> bool:
        """Check if address is authorized signer"""
        return address in self.authorized_signers
    
    def get_all_proposals(self) -> Dict[str, Dict[str, Any]]:
        """Get all proposals (for state hash calculation)"""
        results = {}
        for pid, proposal in self.proposals.items():
            result = asdict(proposal)
            result['status'] = proposal.status.value
            result['proposal_type'] = proposal.proposal_type.value
            results[pid] = result
        return results