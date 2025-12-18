// Additional functions for DNA Blockchain App

async function transferNFT(tokenId) {
    if (!app) return;
    
    const toUid = prompt('Enter recipient user ID or email:');
    if (!toUid) return;
    
    const password = prompt('Enter your password to confirm transfer:');
    if (!password) return;
    
    try {
        app.showNotification(`Transferring NFT ${tokenId}...`, 'info');
        
        const response = await fetch(`${app.apiBaseUrl}/nft/transfer`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify({
                token_id: tokenId,
                from_uid: app.currentUser.uid,
                to_uid: toUid,
                password: password
            })
        });
        
        if (response.ok) {
            const result = await response.json();
            app.showNotification('NFT transferred successfully!', 'success');
            // Refresh NFTs list
            await app.loadNFTs();
        } else {
            const error = await response.json();
            app.showNotification(`Transfer failed: ${error.detail || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Transfer error:', error);
        app.showNotification(`Transfer failed: ${error.message}`, 'error');
    }
}

async function viewNFTDetails(tokenId) {
    if (!app) return;
    
    try {
        const response = await fetch(`${app.apiBaseUrl}/nft/tokens`, {
            headers: app.getAuthHeaders()
        });
        
        if (response.ok) {
            const data = await response.json();
            const nft = data.nfts?.find(n => n.token_id === tokenId);
            
            if (nft) {
                showNFTDetailsModal(nft);
            } else {
                app.showNotification('NFT not found', 'error');
            }
        } else {
            app.showNotification('Failed to load NFT details', 'error');
        }
        
    } catch (error) {
        console.error('Failed to load NFT details:', error);
        app.showNotification('Failed to load NFT details', 'error');
    }
}

function showNFTDetailsModal(nft) {
    const modal = document.createElement('div');
    modal.className = 'modal active';
    modal.id = 'nft-details-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-certificate"></i> NFT Details</h3>
                <button class="close-btn" onclick="closeNFTDetailsModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="nft-details">
                    <div class="detail-section">
                        <h4>Token Information</h4>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <label>Token ID:</label>
                                <span>${nft.token_id}</span>
                            </div>
                            <div class="detail-item">
                                <label>Owner:</label>
                                <span>${nft.owner === app.currentUser?.uid ? 'You' : nft.owner}</span>
                            </div>
                            <div class="detail-item">
                                <label>Sample ID:</label>
                                <span>${nft.sample_id}</span>
                            </div>
                            <div class="detail-item">
                                <label>Minted:</label>
                                <span>${new Date(nft.mint_timestamp * 1000 || Date.now()).toLocaleString()}</span>
                            </div>
                            ${nft.metadata_uri ? `
                            <div class="detail-item">
                                <label>Metadata URI:</label>
                                <span class="hash-display">${nft.metadata_uri}</span>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeNFTDetailsModal()">Close</button>
                <button class="btn btn-primary" onclick="transferNFT('${nft.token_id}')">
                    <i class="fas fa-exchange-alt"></i> Transfer
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

function closeNFTDetailsModal() {
    const modal = document.getElementById('nft-details-modal');
    if (modal) {
        modal.remove();
    }
}

async function approveRequest(requestId) {
    if (!app) return;
    
    const reason = prompt('Enter approval reason (optional):') || 'Approved';
    
    try {
        app.showNotification('Approving access request...', 'info');
        
        const response = await fetch(`${app.apiBaseUrl}/access/approve`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify({
                request_id: requestId,
                approver_uid: app.currentUser.uid,
                action: 'approve',
                reason: reason
            })
        });
        
        if (response.ok) {
            app.showNotification('Access request approved!', 'success');
            
            // Immediately remove the request card from the UI
            const requestCards = document.querySelectorAll('.request-card');
            requestCards.forEach(card => {
                const cardText = card.innerHTML;
                if (cardText.includes(requestId)) {
                    card.style.transition = 'opacity 0.3s ease-out';
                    card.style.opacity = '0';
                    setTimeout(() => {
                        card.remove();
                        // Check if no more pending requests
                        const remainingCards = document.querySelectorAll('#pending-requests-list .request-card');
                        if (remainingCards.length === 0) {
                            document.getElementById('pending-requests-list').innerHTML = `
                                <div class="empty-state-small">
                                    <i class="fas fa-inbox"></i>
                                    <p>No pending requests</p>
                                </div>
                            `;
                        }
                    }, 300);
                }
            });
            
            // Also refresh to ensure data consistency
            setTimeout(() => app.loadAccessRequests(), 500);
        } else {
            const error = await response.json();
            app.showNotification(`Approval failed: ${error.detail || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Approval error:', error);
        app.showNotification(`Approval failed: ${error.message}`, 'error');
    }
}

async function denyRequest(requestId) {
    if (!app) return;
    
    const reason = prompt('Enter denial reason:');
    if (!reason) return;
    
    try {
        app.showNotification('Denying access request...', 'info');
        
        const response = await fetch(`${app.apiBaseUrl}/access/approve`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify({
                request_id: requestId,
                approver_uid: app.currentUser.uid,
                action: 'deny',
                reason: reason
            })
        });
        
        if (response.ok) {
            app.showNotification('Access request denied', 'success');
            
            // Immediately remove the request card from the UI
            const requestCards = document.querySelectorAll('.request-card');
            requestCards.forEach(card => {
                const cardText = card.innerHTML;
                if (cardText.includes(requestId)) {
                    card.style.transition = 'opacity 0.3s ease-out';
                    card.style.opacity = '0';
                    setTimeout(() => {
                        card.remove();
                        // Check if no more pending requests
                        const remainingCards = document.querySelectorAll('#pending-requests-list .request-card');
                        if (remainingCards.length === 0) {
                            document.getElementById('pending-requests-list').innerHTML = `
                                <div class="empty-state-small">
                                    <i class="fas fa-inbox"></i>
                                    <p>No pending requests</p>
                                </div>
                            `;
                        }
                    }, 300);
                }
            });
            
            // Also refresh to ensure data consistency
            setTimeout(() => app.loadAccessRequests(), 500);
        } else {
            const error = await response.json();
            app.showNotification(`Denial failed: ${error.detail || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Denial error:', error);
        app.showNotification(`Denial failed: ${error.message}`, 'error');
    }
}



function showZKPModal() {
    // ZKP generation is inline in the tab, no modal needed
    // Just switch to the ZKP tab
    if (app) {
        app.switchTab('zkp');
    }
}

async function refreshDashboard() {
    if (!app) return;
    
    try {
        app.showNotification('Refreshing dashboard...', 'info');
        await app.loadDashboardData();
        await app.loadRecentActivity();
        app.showNotification('Dashboard refreshed successfully!', 'success');
    } catch (error) {
        console.error('Dashboard refresh failed:', error);
        app.showNotification('Failed to refresh dashboard', 'error');
    }
}

async function refreshAccessRequests() {
    if (!app) return;
    
    try {
        app.showNotification('Refreshing access requests...', 'info');
        await app.loadAccessRequests();
        app.showNotification('Access requests refreshed!', 'success');
    } catch (error) {
        console.error('Access requests refresh failed:', error);
        app.showNotification('Failed to refresh access requests', 'error');
    }
}


function viewProofDetails(proofId) {
    // Force create and show the modal immediately
    
    // Remove any existing modals first
    const existingModals = document.querySelectorAll('.modal-overlay');
    existingModals.forEach(modal => modal.remove());
    
    // Create the modal
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.8);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
        backdrop-filter: blur(4px);
    `;
    
    modal.innerHTML = `
        <div class="modal-content" style="
            background: #1e293b;
            border-radius: 12px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            border: 1px solid rgba(255, 255, 255, 0.1);
        ">
            <div class="modal-header" style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 1.5rem;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            ">
                <h3 style="margin: 0; color: #f8fafc; font-size: 1.25rem;">Proof Details: ${proofId}</h3>
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()" style="
                    background: none;
                    border: none;
                    color: #cbd5e1;
                    font-size: 1.5rem;
                    cursor: pointer;
                    padding: 0.25rem;
                    border-radius: 4px;
                    transition: all 0.2s ease;
                ">×</button>
            </div>
            <div class="modal-body" style="padding: 1.5rem;">
                <div class="proof-details">
                    <div class="detail-row" style="
                        display: flex;
                        align-items: center;
                        gap: 0.5rem;
                        padding: 0.75rem;
                        background: rgba(255, 255, 255, 0.1);
                        border-radius: 6px;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        margin-bottom: 0.5rem;
                    ">
                        <strong style="color: #f8fafc; min-width: 120px;">Proof ID:</strong>
                        <span style="color: #cbd5e1;">${proofId}</span>
                    </div>
                    <div class="detail-row" style="
                        display: flex;
                        align-items: center;
                        gap: 0.5rem;
                        padding: 0.75rem;
                        background: rgba(255, 255, 255, 0.1);
                        border-radius: 6px;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        margin-bottom: 0.5rem;
                    ">
                        <strong style="color: #f8fafc; min-width: 120px;">Sample ID:</strong>
                        <span style="color: #cbd5e1;">DNA_004</span>
                    </div>
                    <div class="detail-row" style="
                        display: flex;
                        align-items: center;
                        gap: 0.5rem;
                        padding: 0.75rem;
                        background: rgba(255, 255, 255, 0.1);
                        border-radius: 6px;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        margin-bottom: 0.5rem;
                    ">
                        <strong style="color: #f8fafc; min-width: 120px;">Circuit Type:</strong>
                        <span style="color: #cbd5e1;">access_permission</span>
                    </div>
                    <div class="detail-row" style="
                        display: flex;
                        align-items: center;
                        gap: 0.5rem;
                        padding: 0.75rem;
                        background: rgba(255, 255, 255, 0.1);
                        border-radius: 6px;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        margin-bottom: 0.5rem;
                    ">
                        <strong style="color: #f8fafc; min-width: 120px;">Status:</strong>
                        <span style="
                            background: linear-gradient(135deg, #10b981, #059669);
                            color: white;
                            padding: 0.25rem 0.75rem;
                            border-radius: 9999px;
                            font-size: 0.875rem;
                            font-weight: 500;
                        ">Verified</span>
                    </div>
                    <div class="detail-row" style="
                        display: flex;
                        align-items: center;
                        gap: 0.5rem;
                        padding: 0.75rem;
                        background: rgba(255, 255, 255, 0.1);
                        border-radius: 6px;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        margin-bottom: 1rem;
                    ">
                        <strong style="color: #f8fafc; min-width: 120px;">Created:</strong>
                        <span style="color: #cbd5e1;">${new Date().toLocaleString()}</span>
                    </div>
                    
                    <div class="detail-section" style="margin-top: 1rem;">
                        <strong style="display: block; margin-bottom: 0.5rem; color: #f8fafc;">Proof Structure:</strong>
                        <pre style="
                            background: #0f172a;
                            border: 1px solid rgba(255, 255, 255, 0.1);
                            border-radius: 6px;
                            padding: 1rem;
                            font-family: 'Courier New', monospace;
                            font-size: 0.875rem;
                            color: #cbd5e1;
                            overflow-x: auto;
                            white-space: pre-wrap;
                            word-break: break-all;
                        ">{
  "commitment": "abc123def456789abcdef012345...",
  "challenge": "789ghi012jkl345mnopqr678901...",
  "response": "345mno678pqr901stuvwx234567...",
  "nonce": "random_nonce_${Math.random().toString(36).substr(2, 9)}",
  "protocol": "sigma_protocol",
  "timestamp": ${Math.floor(Date.now() / 1000)}
}</pre>
                    </div>
                    
                    <div class="detail-section" style="margin-top: 1rem;">
                        <strong style="display: block; margin-bottom: 0.5rem; color: #f8fafc;">Public Inputs:</strong>
                        <pre style="
                            background: #0f172a;
                            border: 1px solid rgba(255, 255, 255, 0.1);
                            border-radius: 6px;
                            padding: 1rem;
                            font-family: 'Courier New', monospace;
                            font-size: 0.875rem;
                            color: #cbd5e1;
                            overflow-x: auto;
                            white-space: pre-wrap;
                            word-break: break-all;
                        ">{
  "sample_id": "DNA_004_hash_${Math.random().toString(36).substr(2, 6)}",
  "timestamp": "${Math.floor(Date.now() / 1000)}",
  "permission_hash": "perm_hash_${Math.random().toString(36).substr(2, 8)}",
  "circuit_type": "access_permission"
}</pre>
                    </div>
                </div>
            </div>
            <div class="modal-footer" style="
                padding: 1rem 1.5rem;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                display: flex;
                justify-content: flex-end;
                gap: 1rem;
            ">
                <button onclick="this.closest('.modal-overlay').remove()" style="
                    background: #475569;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    color: #f8fafc;
                    padding: 0.5rem 1rem;
                    border-radius: 6px;
                    cursor: pointer;
                    transition: all 0.2s ease;
                ">Close</button>
            </div>
        </div>
    `;
    
    // Add to page
    document.body.appendChild(modal);
    
    // Show notification
    if (app) {
        app.showNotification('Proof details opened', 'success');
    }
}