"""
Main ABCI Application for DNA Blockchain Access System
Handles all blockchain transactions and state management
"""

import json
import hashlib
from typing import Dict, Any, Optional
from abci.application import BaseApplication
from abci.server import ABCIServer
from abci.application import ResponseInfo, ResponseCheckTx, ResponseDeliverTx
from abci.application import ResponseQuery, ResponseCommit, ResponseInitChain

from .modules.dna_registry import DNARegistry
from .modules.nft_module import NFTModule
from .modules.access_control import AccessControl
from .modules.multisig import MultiSig
from .modules.zkp_handler import ZKPHandler


class DNABlockchainApp(BaseApplication):
    """Main ABCI application for DNA blockchain system"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize state
        self.state = {
            'height': 0,
            'app_hash': b'',
            'last_block_height': 0
        }
        
        # Initialize modules
        self.dna_registry = DNARegistry()
        self.nft_module = NFTModule()
        self.access_control = AccessControl()
        self.multisig = MultiSig()
        self.zkp_handler = ZKPHandler()
        
        # Transaction types
        self.tx_handlers = {
            'register_dna': self._handle_register_dna,
            'mint_nft': self._handle_mint_nft,
            'request_access': self._handle_request_access,
            'approve_access': self._handle_approve_access,
            'verify_zkp': self._handle_verify_zkp,
            'transfer_nft': self._handle_transfer_nft
        }
    
    def is_healthy(self) -> bool:
        """Check if the blockchain application is healthy"""
        try:
            # Check if all modules are initialized
            return (
                self.dna_registry is not None and
                self.nft_module is not None and
                self.access_control is not None and
                self.multisig is not None and
                self.zkp_handler is not None
            )
        except Exception:
            return False
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        try:
            return {
                'total_samples': self.dna_registry.get_sample_count(),
                'total_nfts': self.nft_module.get_total_supply(),
                'pending_requests': len(self.access_control.get_pending_requests()),
                'verified_proofs': len(self.zkp_handler.get_verified_proofs()),
                'blockchain_height': self.state['height'],
                'total_transactions': getattr(self, 'total_transactions', 0)
            }
        except Exception as e:
            return {
                'total_samples': 0,
                'total_nfts': 0,
                'pending_requests': 0,
                'verified_proofs': 0,
                'blockchain_height': 0,
                'total_transactions': 0,
                'error': str(e)
            }
    
    def info(self, req) -> ResponseInfo:
        """Return information about the application"""
        return ResponseInfo(
            data="DNA Blockchain Access System",
            version="1.0.0",
            app_version=1,
            last_block_height=self.state['last_block_height'],
            last_block_app_hash=self.state['app_hash']
        )
    
    def init_chain(self, req) -> ResponseInitChain:
        """Initialize the blockchain"""
        self.state['height'] = 0
        self.state['app_hash'] = b''
        return ResponseInitChain()
    
    def check_tx(self, req) -> ResponseCheckTx:
        """Validate transaction before including in mempool"""
        try:
            tx_data = json.loads(req.tx.decode('utf-8'))
            tx_type = tx_data.get('type')
            
            if tx_type not in self.tx_handlers:
                return ResponseCheckTx(code=1, log=f"Unknown transaction type: {tx_type}")
            
            # Basic validation
            if not self._validate_transaction(tx_data):
                return ResponseCheckTx(code=1, log="Invalid transaction format")
            
            return ResponseCheckTx(code=0, log="Transaction valid")
            
        except Exception as e:
            return ResponseCheckTx(code=1, log=f"Transaction validation error: {str(e)}")
    
    def deliver_tx(self, req) -> ResponseDeliverTx:
        """Execute transaction and update state"""
        try:
            tx_data = json.loads(req.tx.decode('utf-8'))
            tx_type = tx_data.get('type')
            
            if tx_type not in self.tx_handlers:
                return ResponseDeliverTx(code=1, log=f"Unknown transaction type: {tx_type}")
            
            # Execute transaction
            result = self.tx_handlers[tx_type](tx_data)
            
            if result['success']:
                return ResponseDeliverTx(
                    code=0,
                    log=result['message']
                )
            else:
                return ResponseDeliverTx(code=1, log=result['message'])
                
        except Exception as e:
            return ResponseDeliverTx(code=1, log=f"Transaction execution error: {str(e)}")
    
    def commit(self, req) -> ResponseCommit:
        """Commit the current state"""
        # Calculate app hash
        state_json = json.dumps(self._get_state_for_hash(), sort_keys=True)
        app_hash = hashlib.sha256(state_json.encode()).digest()
        
        self.state['app_hash'] = app_hash
        self.state['height'] += 1
        self.state['last_block_height'] = self.state['height']
        
        return ResponseCommit(data=app_hash)
    
    def query(self, req) -> ResponseQuery:
        """Handle queries to the application state"""
        try:
            path = req.path.decode('utf-8')
            data = req.data.decode('utf-8') if req.data else ''
            
            if path == '/dna/sample':
                result = self.dna_registry.get_sample(data)
            elif path == '/nft/token':
                result = self.nft_module.get_token(data)
            elif path == '/access/permissions':
                result = self.access_control.get_permissions(data)
            elif path == '/multisig/proposal':
                result = self.multisig.get_proposal(data)
            else:
                return ResponseQuery(code=1, log=f"Unknown query path: {path}")
            
            return ResponseQuery(
                code=0,
                value=json.dumps(result).encode('utf-8'),
                log="Query successful"
            )
            
        except Exception as e:
            return ResponseQuery(code=1, log=f"Query error: {str(e)}")
    
    def _validate_transaction(self, tx_data: Dict[str, Any]) -> bool:
        """Basic transaction validation"""
        required_fields = ['type', 'sender', 'timestamp']
        return all(field in tx_data for field in required_fields)
    
    def _handle_register_dna(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle DNA sample registration"""
        return self.dna_registry.register_sample(
            sample_id=tx_data['sample_id'],
            owner=tx_data['sender'],
            cid=tx_data['cid'],
            file_hash=tx_data['file_hash'],
            metadata=tx_data.get('metadata', {})
        )
    
    def _handle_mint_nft(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle NFT minting"""
        return self.nft_module.mint_token(
            token_id=tx_data['token_id'],
            owner=tx_data['sender'],
            sample_id=tx_data['sample_id'],
            metadata_uri=tx_data['metadata_uri']
        )
    
    def _handle_request_access(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle access request"""
        return self.access_control.request_access(
            requester=tx_data['sender'],
            sample_id=tx_data['sample_id'],
            purpose=tx_data['purpose']
        )
    
    def _handle_approve_access(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle access approval (multisig)"""
        return self.multisig.approve_access(
            approver=tx_data['sender'],
            request_id=tx_data['request_id'],
            signature=tx_data['signature']
        )
    
    def _handle_verify_zkp(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ZKP verification"""
        return self.zkp_handler.verify_proof(
            proof=tx_data['proof'],
            public_inputs=tx_data['public_inputs'],
            request_id=tx_data['request_id']
        )
    
    def _handle_transfer_nft(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle NFT transfer"""
        return self.nft_module.transfer_token(
            token_id=tx_data['token_id'],
            from_address=tx_data['sender'],
            to_address=tx_data['to_address']
        )
    
    # Public API methods for external access
    def register_dna_sample(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a DNA sample"""
        return self.dna_registry.register_sample(
            sample_id=sample_data['sample_id'],
            owner=sample_data['owner'],
            file_hash=sample_data['file_hash'],
            cid=sample_data['cid'],
            metadata=sample_data['metadata']
        )
    
    def get_sample(self, sample_id: str) -> Optional[Dict[str, Any]]:
        """Get DNA sample by ID"""
        return self.dna_registry.get_sample(sample_id)
    
    def check_access_permission(self, user_id: str, sample_id: str) -> bool:
        """Check if user has access permission to sample"""
        return self.access_control.check_access_permission(user_id, sample_id)
    
    def mint_nft(self, nft_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mint an NFT"""
        return self.nft_module.mint_token(
            token_id=nft_data['token_id'],
            owner=nft_data['owner'],
            sample_id=nft_data['sample_id'],
            metadata_uri=nft_data['metadata_uri']
        )
    
    def get_nft(self, token_id: str) -> Optional[Dict[str, Any]]:
        """Get NFT by token ID"""
        return self.nft_module.get_token(token_id)
    
    def transfer_nft(self, token_id: str, from_address: str, to_address: str) -> Dict[str, Any]:
        """Transfer NFT"""
        return self.nft_module.transfer_token(token_id, from_address, to_address)
    
    def request_access(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Request access to a sample"""
        return self.access_control.request_access(
            requester=request_data['requester'],
            sample_id=request_data['sample_id'],
            purpose=request_data['purpose']
        )
    
    def get_access_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get access request by ID"""
        return self.access_control.get_request(request_id)
    
    def approve_access_request(self, request_id: str, approver: str, reason: str) -> Dict[str, Any]:
        """Approve access request"""
        return self.access_control.approve_request(request_id, approver, reason)
    
    def deny_access_request(self, request_id: str, approver: str, reason: str) -> Dict[str, Any]:
        """Deny access request"""
        return self.access_control.deny_request(request_id, approver, reason)
    
    def store_zkp(self, proof_id: str, prover: str, circuit_type: str, proof: str, public_inputs: str) -> Dict[str, Any]:
        """Store ZKP proof"""
        return self.zkp_handler.store_proof(proof_id, prover, circuit_type, proof, public_inputs)
    
    def verify_zkp(self, request_id: str, verifier: str, verified: bool, circuit_type: str) -> Dict[str, Any]:
        """Verify ZKP proof"""
        return self.zkp_handler.verify_proof_result(request_id, verifier, verified, circuit_type)

    def _get_state_for_hash(self) -> Dict[str, Any]:
        """Get state data for hash calculation"""
        return {
            'dna_samples': self.dna_registry.get_all_samples(),
            'nft_tokens': self.nft_module.get_all_tokens(),
            'access_requests': self.access_control.get_all_requests(),
            'multisig_proposals': self.multisig.get_all_proposals(),
            'height': self.state['height']
        }


def run_abci_server(port: int = 26658):
    """Run the ABCI server"""
    app = DNABlockchainApp()
    server = ABCIServer(app=app, port=port)
    server.run()


if __name__ == '__main__':
    run_abci_server()