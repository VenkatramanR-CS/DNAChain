// DNA Blockchain Access System - Frontend Application

class DNABlockchainApp {
    constructor() {
        this.apiBaseUrl = 'http://localhost:8000';
        this.currentUser = 'user123';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadDashboard();
        this.startPeriodicUpdates();
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tabName = e.target.closest('.nav-btn').dataset.tab;
                this.switchTab(tabName);
            });
        });

        // Modal close events
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                this.closeModal(e.target.id);
            }
        });

        // Form submissions
        document.getElementById('upload-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.uploadSample();
        });
    }

    switchTab(tabName) {
        // Update nav buttons
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');

        // Load tab-specific data
        this.loadTabData(tabName);
    }

    async loadTabData(tabName) {
        switch (tabName) {
            case 'dashboard':
                await this.loadDashboard();
                break;
            case 'samples':
                await this.loadSamples();
                break;
            case 'nfts':
                await this.loadNFTs();
                break;
            case 'access':
                await this.loadAccessRequests();
                break;
            case 'zkp':
                await this.loadZKProofs();
                break;
        }
    }

    async loadDashboard() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/health`);
            const data = await response.json();

            if (response.ok) {
                // Update statistics
                document.getElementById('total-samples').textContent = data.total_samples;
                document.getElementById('total-nfts').textContent = data.total_nfts;
                document.getElementById('pending-requests').textContent = data.pending_requests;
                document.getElementById('verified-proofs').textContent = data.verified_proofs;

                // Update system status
                document.getElementById('blockchain-status').textContent = data.blockchain_status;
                document.getElementById('api-status').textContent = 'Online';
                document.getElementById('system-uptime').textContent = data.uptime;

                // Load recent activity
                this.loadRecentActivity();
            }
        } catch (error) {
            console.error('Failed to load dashboard:', error);
            this.showNotification('Failed to load dashboard data', 'error');
        }
    }

    loadRecentActivity() {
        const activities = [
            {
                icon: 'fas fa-upload',
                text: 'DNA sample DNA_001 uploaded',
                time: '2 minutes ago',
                type: 'upload'
            },
            {
                icon: 'fas fa-certificate',
                text: 'NFT NFT_001 minted',
                time: '5 minutes ago',
                type: 'mint'
            },
            {
                icon: 'fas fa-key',
                text: 'Access request submitted',
                time: '10 minutes ago',
                type: 'access'
            },
            {
                icon: 'fas fa-shield-check',
                text: 'ZK proof verified',
                time: '15 minutes ago',
                type: 'zkp'
            }
        ];

        const activityList = document.getElementById('recent-activity');
        activityList.innerHTML = activities.map(activity => `
            <div class="activity-item">
                <div class="activity-icon">
                    <i class="${activity.icon}"></i>
                </div>
                <div class="activity-text">${activity.text}</div>
                <div class="activity-time">${activity.time}</div>
            </div>
        `).join('');
    }

    async loadSamples() {
        // Simulate loading samples
        const samples = [
            {
                sample_id: 'DNA_001',
                owner: 'user123',
                type: 'saliva',
                status: 'active',
                created_at: new Date().toISOString(),
                file_hash: 'abc123...'
            },
            {
                sample_id: 'DNA_002',
                owner: 'user456',
                type: 'blood',
                status: 'active',
                created_at: new Date().toISOString(),
                file_hash: 'def456...'
            }
        ];

        const samplesGrid = document.getElementById('samples-grid');
        samplesGrid.innerHTML = samples.map(sample => `
            <div class="sample-card">
                <div class="card-header">
                    <div class="card-title">${sample.sample_id}</div>
                    <div class="card-status status-${sample.status}">${sample.status}</div>
                </div>
                <div class="card-info">
                    <div class="info-item">
                        <span class="info-label">Owner:</span>
                        <span class="info-value">${sample.owner}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Type:</span>
                        <span class="info-value">${sample.type}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Created:</span>
                        <span class="info-value">${new Date(sample.created_at).toLocaleDateString()}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Hash:</span>
                        <span class="info-value">${sample.file_hash.substring(0, 10)}...</span>
                    </div>
                </div>
                <div class="card-actions">
                    <button class="btn btn-primary" onclick="app.viewSample('${sample.sample_id}')">
                        <i class="fas fa-eye"></i> View
                    </button>
                    <button class="btn btn-secondary" onclick="app.downloadSample('${sample.sample_id}')">
                        <i class="fas fa-download"></i> Download
                    </button>
                </div>
            </div>
        `).join('');
    }

    async loadNFTs() {
        // Simulate loading NFTs
        const nfts = [
            {
                token_id: 'NFT_001',
                owner: 'user123',
                sample_id: 'DNA_001',
                metadata_uri: 'https://example.com/metadata/NFT_001.json',
                created_at: new Date().toISOString()
            }
        ];

        const nftsGrid = document.getElementById('nfts-grid');
        nftsGrid.innerHTML = nfts.map(nft => `
            <div class="nft-card">
                <div class="card-header">
                    <div class="card-title">${nft.token_id}</div>
                    <div class="card-status status-active">Active</div>
                </div>
                <div class="card-info">
                    <div class="info-item">
                        <span class="info-label">Owner:</span>
                        <span class="info-value">${nft.owner}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Sample:</span>
                        <span class="info-value">${nft.sample_id}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Created:</span>
                        <span class="info-value">${new Date(nft.created_at).toLocaleDateString()}</span>
                    </div>
                </div>
                <div class="card-actions">
                    <button class="btn btn-primary" onclick="app.viewNFT('${nft.token_id}')">
                        <i class="fas fa-eye"></i> View
                    </button>
                    <button class="btn btn-secondary" onclick="app.transferNFT('${nft.token_id}')">
                        <i class="fas fa-exchange-alt"></i> Transfer
                    </button>
                </div>
            </div>
        `).join('');
    }

    async loadAccessRequests() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/access/requests/pending`);
            const data = await response.json();

            if (response.ok) {
                this.displayPendingRequests(data.requests || []);
            }
        } catch (error) {
            console.error('Failed to load access requests:', error);
            // Show simulated data
            this.displayPendingRequests([
                {
                    request_id: 'req_001',
                    requester: 'researcher456',
                    sample_id: 'DNA_001',
                    purpose: 'Medical research on genetic markers',
                    status: 'pending',
                    created_at: new Date().toISOString(),
                    approvals: [],
                    required_approvals: 2
                }
            ]);
        }
    }

    displayPendingRequests(requests) {
        const pendingList = document.getElementById('pending-requests-list');
        pendingList.innerHTML = requests.map(request => `
            <div class="request-card">
                <div class="request-header">
                    <div class="request-id">${request.request_id}</div>
                    <div class="request-status status-${request.status}">${request.status}</div>
                </div>
                <div class="request-info">
                    <div class="info-item">
                        <span class="info-label">Requester:</span>
                        <span class="info-value">${request.requester}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Sample:</span>
                        <span class="info-value">${request.sample_id}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Approvals:</span>
                        <span class="info-value">${request.approvals.length}/${request.required_approvals}</span>
                    </div>
                    <div class="request-purpose">${request.purpose}</div>
                </div>
                <div class="request-actions">
                    <button class="btn btn-success" onclick="app.approveRequest('${request.request_id}')">
                        <i class="fas fa-check"></i> Approve
                    </button>
                    <button class="btn btn-danger" onclick="app.denyRequest('${request.request_id}')">
                        <i class="fas fa-times"></i> Deny
                    </button>
                </div>
            </div>
        `).join('');
    }

    async loadZKProofs() {
        // Simulate loading verified proofs
        const proofs = [
            {
                proof_id: 'proof_001',
                prover: 'researcher456',
                circuit_type: 'access_permission',
                verified: true,
                created_at: new Date().toISOString()
            }
        ];

        const proofsList = document.getElementById('verified-proofs-list');
        proofsList.innerHTML = proofs.map(proof => `
            <div class="proof-card">
                <div class="proof-header">
                    <div class="proof-type">${proof.circuit_type}</div>
                    <div class="proof-status">✓ Verified</div>
                </div>
                <div class="proof-details">
                    <div>Proof ID: ${proof.proof_id}</div>
                    <div>Prover: ${proof.prover}</div>
                    <div>Created: ${new Date(proof.created_at).toLocaleDateString()}</div>
                </div>
            </div>
        `).join('');
    }

    // Modal functions
    showModal(modalId) {
        document.getElementById(modalId).classList.add('active');
    }

    closeModal(modalId) {
        document.getElementById(modalId).classList.remove('active');
    }

    // Upload sample
    async uploadSample() {
        const formData = {
            sample_id: document.getElementById('sample-id').value,
            owner: document.getElementById('owner-address').value,
            password: document.getElementById('encryption-password').value,
            metadata: {
                type: document.getElementById('sample-type').value,
                collection_date: document.getElementById('collection-date').value
            }
        };

        const fileInput = document.getElementById('dna-file');
        if (fileInput.files.length === 0) {
            this.showNotification('Please select a DNA file', 'error');
            return;
        }

        this.showLoading(true);

        try {
            // Read file as base64
            const file = fileInput.files[0];
            const fileData = await this.fileToBase64(file);

            const uploadData = {
                ...formData,
                file_data: fileData
            };

            const response = await fetch(`${this.apiBaseUrl}/dna/upload`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(uploadData)
            });

            const result = await response.json();

            if (response.ok && result.success) {
                this.showNotification('DNA sample uploaded successfully!', 'success');
                this.closeModal('upload-modal');
                this.loadSamples();
            } else {
                this.showNotification(result.error || 'Upload failed', 'error');
            }
        } catch (error) {
            console.error('Upload error:', error);
            this.showNotification('Upload failed: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    // Mint NFT
    async mintNFT() {
        const formData = {
            token_id: document.getElementById('token-id').value,
            sample_id: document.getElementById('nft-sample-id').value,
            owner: document.getElementById('nft-owner-address').value,
            metadata_uri: document.getElementById('metadata-uri').value
        };

        this.showLoading(true);

        try {
            const response = await fetch(`${this.apiBaseUrl}/nft/mint`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });

            const result = await response.json();

            if (response.ok && result.success) {
                this.showNotification('NFT minted successfully!', 'success');
                this.closeModal('mint-modal');
                this.loadNFTs();
            } else {
                this.showNotification(result.error || 'Minting failed', 'error');
            }
        } catch (error) {
            console.error('Mint error:', error);
            this.showNotification('Minting failed: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    // Request access
    async requestAccess() {
        const formData = {
            requester: document.getElementById('requester-address').value,
            sample_id: document.getElementById('access-sample-id').value,
            purpose: document.getElementById('access-purpose').value,
            expiry_hours: parseInt(document.getElementById('expiry-hours').value)
        };

        this.showLoading(true);

        try {
            const response = await fetch(`${this.apiBaseUrl}/access/request`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });

            const result = await response.json();

            if (response.ok && result.success) {
                this.showNotification('Access request submitted successfully!', 'success');
                this.closeModal('access-request-modal');
                this.loadAccessRequests();
            } else {
                this.showNotification(result.error || 'Request failed', 'error');
            }
        } catch (error) {
            console.error('Request error:', error);
            this.showNotification('Request failed: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    // Generate ZK Proof
    async generateZKProof() {
        const circuitType = document.getElementById('circuit-type').value;
        const sampleId = document.getElementById('zkp-sample-id').value;
        const userSecret = document.getElementById('zkp-user-secret').value;

        if (!sampleId || !userSecret) {
            this.showNotification('Please fill in all fields', 'error');
            return;
        }

        this.showLoading(true);

        try {
            // Simulate proof generation
            const proofData = {
                proof: this.generateMockProof(),
                public_inputs: {
                    user_id: this.currentUser,
                    sample_id: sampleId,
                    permission_hash: 'permission_hash_123'
                },
                request_id: 'req_' + Date.now(),
                circuit_type: circuitType
            };

            const response = await fetch(`${this.apiBaseUrl}/zkp/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(proofData)
            });

            const result = await response.json();

            if (response.ok && result.success) {
                this.showNotification('ZK proof generated and verified!', 'success');
                this.loadZKProofs();
            } else {
                this.showNotification(result.error || 'Proof generation failed', 'error');
            }
        } catch (error) {
            console.error('ZKP error:', error);
            this.showNotification('Proof generation failed: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    // Utility functions
    fileToBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.readAsDataURL(file);
            reader.onload = () => {
                const base64 = reader.result.split(',')[1];
                resolve(base64);
            };
            reader.onerror = error => reject(error);
        });
    }

    generateMockProof() {
        // Generate a mock proof for demonstration
        const chars = '0123456789abcdef';
        let proof = '';
        for (let i = 0; i < 64; i++) {
            proof += chars[Math.floor(Math.random() * chars.length)];
        }
        return proof;
    }

    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        if (show) {
            overlay.classList.add('active');
        } else {
            overlay.classList.remove('active');
        }
    }

    showNotification(message, type = 'info') {
        const container = document.getElementById('notification-container');
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        const iconMap = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        };

        notification.innerHTML = `
            <i class="notification-icon ${iconMap[type]}"></i>
            <span>${message}</span>
        `;

        container.appendChild(notification);

        // Auto remove after 5 seconds
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }

    startPeriodicUpdates() {
        // Update dashboard every 30 seconds
        setInterval(() => {
            if (document.querySelector('.nav-btn[data-tab="dashboard"]').classList.contains('active')) {
                this.loadDashboard();
            }
        }, 30000);
    }

    // Action handlers
    viewSample(sampleId) {
        this.showNotification(`Viewing sample: ${sampleId}`, 'info');
    }

    downloadSample(sampleId) {
        this.showNotification(`Downloading sample: ${sampleId}`, 'info');
    }

    viewNFT(tokenId) {
        this.showNotification(`Viewing NFT: ${tokenId}`, 'info');
    }

    transferNFT(tokenId) {
        this.showNotification(`Transfer NFT: ${tokenId}`, 'info');
    }

    approveRequest(requestId) {
        this.showNotification(`Approving request: ${requestId}`, 'success');
    }

    denyRequest(requestId) {
        this.showNotification(`Denying request: ${requestId}`, 'warning');
    }
}

// Global functions for HTML onclick handlers
function showUploadModal() {
    app.showModal('upload-modal');
}

function showMintModal() {
    app.showModal('mint-modal');
}

function showAccessRequestModal() {
    app.showModal('access-request-modal');
}

function showZKPModal() {
    // For now, just focus on the ZKP form
    app.switchTab('zkp');
}

function closeModal(modalId) {
    app.closeModal(modalId);
}

function uploadSample() {
    app.uploadSample();
}

function mintNFT() {
    app.mintNFT();
}

function requestAccess() {
    app.requestAccess();
}

function generateZKProof() {
    app.generateZKProof();
}

// Initialize the application
const app = new DNABlockchainApp();