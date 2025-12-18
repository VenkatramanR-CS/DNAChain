// DNA Blockchain Access System - Modern Frontend Application with Firebase Auth

class DNABlockchainApp {
    constructor() {
        this.apiBaseUrl = 'http://localhost:8001';
        this.currentUser = null;
        this.authToken = null;
        this.firebase = null;
        this.auth = null;
        this.db = null;
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.initializeAuthInterface();
        this.initializeFirebase();
        
        // Ensure auth modal is shown initially
        setTimeout(() => {
            if (!this.currentUser) {
                this.showAuthModal();
            }
        }, 1000);
    }

    initializeFirebase() {
        // Wait for Firebase to be loaded
        let attempts = 0;
        const maxAttempts = 30; // 3 seconds max wait
        
        const checkFirebase = () => {
            attempts++;
            
            if (window.firebaseAuth && window.firebaseDb) {
                this.auth = window.firebaseAuth;
                this.db = window.firebaseDb;
                this.setupAuthStateListener();

                this.showNotification('Firebase authentication ready!', 'success');
            } else if (attempts >= maxAttempts) {

                this.showNotification('Running in demo mode - Firebase not configured', 'info');
                this.auth = null;
                this.db = null;
                // Force show auth modal in demo mode
                this.showAuthModal();
            } else {
                setTimeout(checkFirebase, 100);
            }
        };
        
        // Start checking immediately
        setTimeout(checkFirebase, 100);
    }

    setupAuthStateListener() {
        if (!this.auth || !window.onAuthStateChanged) {

            return;
        }
        
        window.onAuthStateChanged(this.auth, async (user) => {
            if (user) {

                
                // Get Firebase ID token for API authentication
                try {
                    this.authToken = await user.getIdToken();
                } catch (error) {
                    console.error('Failed to get ID token:', error);
                    this.authToken = null;
                }
                
                this.currentUser = {
                    uid: user.uid,
                    email: user.email,
                    name: user.displayName || user.email.split('@')[0],
                    photoURL: user.photoURL,
                    provider: user.providerData[0]?.providerId || 'email'
                };
                this.hideAuthModal();
                this.showMainApp();
                this.saveUserProfile(user);
            } else {

                this.currentUser = null;
                this.authToken = null;
                this.showAuthModal();
            }
        });
    }

    async saveUserProfile(user) {
        try {
            const userRef = window.doc(this.db, 'users', user.uid);
            const userDoc = await window.getDoc(userRef);
            
            if (!userDoc.exists()) {
                // Create new user profile
                await window.setDoc(userRef, {
                    uid: user.uid,
                    email: user.email,
                    displayName: user.displayName || user.email.split('@')[0],
                    photoURL: user.photoURL || null,
                    provider: user.providerData[0]?.providerId || 'email',
                    role: 'user', // Default role
                    createdAt: new Date().toISOString(),
                    lastLogin: new Date().toISOString()
                });

            } else {
                // Update last login
                await window.setDoc(userRef, {
                    lastLogin: new Date().toISOString()
                }, { merge: true });

            }
        } catch (error) {
            console.error('Error saving user profile:', error);
        }
    }

    showAuthModal() {
        document.getElementById('auth-modal').classList.add('active');
        document.getElementById('main-app').style.display = 'none';
    }

    initializeAuthInterface() {
        // Set up auth tab switching
        document.querySelectorAll('.auth-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabType = e.target.closest('.auth-tab').dataset.tab;
                this.switchAuthTab(tabType);
            });
        });

        // Set up form submissions
        document.getElementById('login-form-element')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.getElementById('register-form-element')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister();
        });

        // Set up password strength checking
        document.getElementById('register-password')?.addEventListener('input', (e) => {
            this.checkPasswordStrength(e.target.value);
        });

        // Set up password confirmation
        document.getElementById('register-confirm-password')?.addEventListener('input', (e) => {
            this.validatePasswordMatch();
        });

        // Set up social login
        document.getElementById('google-login')?.addEventListener('click', () => {
            this.handleSocialLogin('google');
        });

        document.getElementById('github-login')?.addEventListener('click', () => {
            this.handleSocialLogin('github');
        });
    }

    switchAuthTab(tabType) {
        // Update tab buttons
        document.querySelectorAll('.auth-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabType}"]`).classList.add('active');

        // Update form visibility
        document.querySelectorAll('.auth-form').forEach(form => {
            form.classList.remove('active');
        });
        document.getElementById(`${tabType}-form`).classList.add('active');

        // Update header text
        const formTitle = document.getElementById('form-title');
        const formSubtitle = document.getElementById('form-subtitle');

        if (tabType === 'login') {
            formTitle.textContent = 'Welcome Back';
            formSubtitle.textContent = 'Sign in to access your secure DNA vault';
        } else {
            formTitle.textContent = 'Create Account';
            formSubtitle.textContent = 'Join the secure DNA blockchain network';
        }
    }

    async handleLogin() {
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        const rememberMe = document.getElementById('remember-me').checked;

        // Basic validation
        if (!email || !password) {
            this.showNotification('Please fill in all fields', 'error');
            return;
        }

        if (!this.auth) {
            // Fallback to demo mode

            await this.handleDemoLogin(email, password, rememberMe);
            return;
        }

        const loginBtn = document.querySelector('#login-form-element .btn-primary');
        this.setButtonLoading(loginBtn, true);

        try {
            // Sign in with Firebase Auth
            const userCredential = await window.signInWithEmailAndPassword(this.auth, email, password);
            const user = userCredential.user;
            

            this.showNotification('Login successful! Welcome back.', 'success');
            
            // Remember me functionality
            if (rememberMe) {
                localStorage.setItem('dna_remember_user', 'true');
            } else {
                localStorage.removeItem('dna_remember_user');
            }

        } catch (error) {
            console.error('Login error:', error);
            let errorMessage = 'Login failed. Please try again.';
            
            switch (error.code) {
                case 'auth/user-not-found':
                    errorMessage = 'No account found with this email address.';
                    break;
                case 'auth/wrong-password':
                    errorMessage = 'Incorrect password. Please try again.';
                    break;
                case 'auth/invalid-email':
                    errorMessage = 'Invalid email address format.';
                    break;
                case 'auth/user-disabled':
                    errorMessage = 'This account has been disabled.';
                    break;
                case 'auth/too-many-requests':
                    errorMessage = 'Too many failed attempts. Please try again later.';
                    break;
                default:
                    errorMessage = error.message;
            }
            
            this.showNotification(errorMessage, 'error');
        } finally {
            this.setButtonLoading(loginBtn, false);
        }
    }

    async handleRegister() {
        const name = document.getElementById('register-name').value;
        const email = document.getElementById('register-email').value;
        const role = document.getElementById('register-role').value;
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        const agreeTerms = document.getElementById('agree-terms').checked;

        // Validation
        if (!name || !email || !role || !password || !confirmPassword) {
            this.showNotification('Please fill in all fields', 'error');
            return;
        }

        if (password !== confirmPassword) {
            this.showNotification('Passwords do not match', 'error');
            return;
        }

        if (!agreeTerms) {
            this.showNotification('Please agree to the terms and conditions', 'error');
            return;
        }

        if (password.length < 8) {
            this.showNotification('Password must be at least 8 characters long', 'error');
            return;
        }

        if (!this.auth) {
            // Fallback to demo mode

            await this.handleDemoRegister(name, email, role, password);
            return;
        }

        const registerBtn = document.querySelector('#register-form-element .btn-primary');
        this.setButtonLoading(registerBtn, true);

        try {
            // Create user with Firebase Auth
            const userCredential = await window.createUserWithEmailAndPassword(this.auth, email, password);
            const user = userCredential.user;
            
            // Update user profile with display name
            await user.updateProfile({
                displayName: name
            });
            
            // Save additional user data to Firestore
            const userRef = window.doc(this.db, 'users', user.uid);
            await window.setDoc(userRef, {
                uid: user.uid,
                email: email,
                displayName: name,
                role: role,
                provider: 'email',
                createdAt: new Date().toISOString(),
                lastLogin: new Date().toISOString(),
                termsAccepted: true,
                termsAcceptedAt: new Date().toISOString()
            });
            

            this.showNotification('Account created successfully! Welcome to DNA Blockchain.', 'success');

        } catch (error) {
            console.error('Registration error:', error);
            let errorMessage = 'Registration failed. Please try again.';
            
            switch (error.code) {
                case 'auth/email-already-in-use':
                    errorMessage = 'An account with this email already exists.';
                    break;
                case 'auth/invalid-email':
                    errorMessage = 'Invalid email address format.';
                    break;
                case 'auth/weak-password':
                    errorMessage = 'Password is too weak. Please choose a stronger password.';
                    break;
                case 'auth/operation-not-allowed':
                    errorMessage = 'Email/password accounts are not enabled.';
                    break;
                default:
                    errorMessage = error.message;
            }
            
            this.showNotification(errorMessage, 'error');
        } finally {
            this.setButtonLoading(registerBtn, false);
        }
    }

    async handleSocialLogin(providerName) {
        if (!this.auth) {
            this.showNotification('Firebase not initialized. Please refresh the page.', 'error');
            return;
        }

        let provider;
        let buttonSelector;

        // Set up the provider
        switch (providerName) {
            case 'google':
                provider = new window.GoogleAuthProvider();
                provider.addScope('profile');
                provider.addScope('email');
                buttonSelector = '#google-login';
                break;
            case 'github':
                provider = new window.GithubAuthProvider();
                provider.addScope('user:email');
                buttonSelector = '#github-login';
                break;
            default:
                this.showNotification('Unsupported login provider', 'error');
                return;
        }

        const socialBtn = document.querySelector(buttonSelector);
        this.setButtonLoading(socialBtn, true);

        try {
            // Sign in with popup
            const result = await window.signInWithPopup(this.auth, provider);
            const user = result.user;
            
            // Get additional user info from the provider
            const credential = providerName === 'google' 
                ? window.GoogleAuthProvider.credentialFromResult(result)
                : window.GithubAuthProvider.credentialFromResult(result);
            

            
            this.showNotification(`Successfully signed in with ${providerName.charAt(0).toUpperCase() + providerName.slice(1)}!`, 'success');
            
            // Save additional provider-specific data
            const userRef = window.doc(this.db, 'users', user.uid);
            const userData = {
                uid: user.uid,
                email: user.email,
                displayName: user.displayName || user.email.split('@')[0],
                photoURL: user.photoURL || null,
                provider: providerName,
                lastLogin: new Date().toISOString()
            };
            
            // Check if user exists, if not create profile
            const userDoc = await window.getDoc(userRef);
            if (!userDoc.exists()) {
                userData.createdAt = new Date().toISOString();
                userData.role = 'user'; // Default role for social login
            }
            
            await window.setDoc(userRef, userData, { merge: true });

        } catch (error) {
            console.error(`${providerName} login error:`, error);
            let errorMessage = `${providerName.charAt(0).toUpperCase() + providerName.slice(1)} login failed.`;
            
            switch (error.code) {
                case 'auth/account-exists-with-different-credential':
                    errorMessage = 'An account already exists with the same email but different sign-in credentials.';
                    break;
                case 'auth/auth-domain-config-required':
                    errorMessage = 'Authentication domain configuration is required.';
                    break;
                case 'auth/cancelled-popup-request':
                    errorMessage = 'Login was cancelled.';
                    return; // Don't show error for user cancellation
                case 'auth/operation-not-allowed':
                    errorMessage = `${providerName.charAt(0).toUpperCase() + providerName.slice(1)} login is not enabled.`;
                    break;
                case 'auth/popup-blocked':
                    errorMessage = 'Login popup was blocked by your browser. Please allow popups and try again.';
                    break;
                case 'auth/popup-closed-by-user':
                    errorMessage = 'Login popup was closed before completing sign-in.';
                    return; // Don't show error for user cancellation
                case 'auth/unauthorized-domain':
                    errorMessage = 'This domain is not authorized for authentication.';
                    break;
                default:
                    errorMessage = error.message;
            }
            
            this.showNotification(errorMessage, 'error');
        } finally {
            this.setButtonLoading(socialBtn, false);
        }
    }

    checkPasswordStrength(password) {
        const strengthBar = document.querySelector('.strength-fill');
        const strengthText = document.querySelector('.strength-text');
        
        if (!strengthBar || !strengthText) return;
        
        let strength = 0;
        let strengthLabel = 'Very Weak';
        let color = '#ef4444';

        if (password.length >= 8) strength += 1;
        if (/[a-z]/.test(password)) strength += 1;
        if (/[A-Z]/.test(password)) strength += 1;
        if (/[0-9]/.test(password)) strength += 1;
        if (/[^A-Za-z0-9]/.test(password)) strength += 1;

        switch (strength) {
            case 0:
            case 1:
                strengthLabel = 'Very Weak';
                color = '#ef4444';
                break;
            case 2:
                strengthLabel = 'Weak';
                color = '#f59e0b';
                break;
            case 3:
                strengthLabel = 'Fair';
                color = '#eab308';
                break;
            case 4:
                strengthLabel = 'Good';
                color = '#22c55e';
                break;
            case 5:
                strengthLabel = 'Strong';
                color = '#10b981';
                break;
        }

        const percentage = (strength / 5) * 100;
        strengthBar.style.width = `${percentage}%`;
        strengthBar.style.background = color;
        strengthText.textContent = `Password strength: ${strengthLabel}`;
        strengthText.style.color = color;
    }

    validatePasswordMatch() {
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        const confirmInput = document.getElementById('register-confirm-password');

        if (confirmPassword && password !== confirmPassword) {
            confirmInput.style.borderColor = '#ef4444';
        } else {
            confirmInput.style.borderColor = '';
        }
    }

    setButtonLoading(button, loading) {
        if (loading) {
            button.classList.add('loading');
            button.disabled = true;
        } else {
            button.classList.remove('loading');
            button.disabled = false;
        }
    }

    hideAuthModal() {
        document.getElementById('auth-modal').classList.remove('active');
    }

    showMainApp() {
        document.getElementById('main-app').style.display = 'flex';
        this.updateUserInterface();
        this.initializeMainAppData();
        this.showNotification(`Welcome back, ${this.currentUser.name}!`, 'success');
    }

    async initializeMainAppData() {
        // Update system status
        document.getElementById('blockchain-status').textContent = 'Active';
        document.getElementById('firebase-status').textContent = this.auth ? 'Connected' : 'Demo Mode';
        document.getElementById('api-status').textContent = 'Online';
        document.getElementById('system-uptime').textContent = 'Running';
        
        // Load real data from API or use demo data
        try {
            await this.loadDashboardData();
        } catch (error) {

            this.showNotification('Unable to connect to server', 'error');
        }
        
        // Load initial tab data
        await this.loadSamples();
        await this.loadNFTs();
        await this.loadAccessRequests();
        await this.loadZKProofs();
        
        // Setup tab navigation
        this.setupTabNavigation();
        
        // Load recent activity
        await this.loadRecentActivity();
    }

    async loadDashboardData() {
        try {

            
            // Use the dedicated dashboard counts endpoint
            const response = await fetch(`${this.apiBaseUrl}/dashboard/counts`, {
                headers: this.getAuthHeaders()
            });
            
            if (response.ok) {
                const data = await response.json();
                
                // Update dashboard counts with REAL data
                document.getElementById('total-samples').textContent = data.total_samples.toString();
                document.getElementById('total-nfts').textContent = data.total_nfts.toString();
                document.getElementById('pending-requests').textContent = data.pending_requests.toString();
                document.getElementById('verified-proofs').textContent = data.verified_proofs.toString();
                

                
                // Show success message if we have real data
                if (data.total_samples > 0 || data.total_nfts > 0) {
                    this.showNotification('Dashboard loaded with your real data!', 'success');
                }
            } else {
                throw new Error('Dashboard API not available');
            }
            
        } catch (error) {

            throw error;
        }
    }



    updateUserInterface() {
        if (this.currentUser) {
            // Update user info in header
            const userAvatar = document.querySelector('.user-avatar');
            const currentUserName = document.getElementById('current-user-name');
            const currentUserEmail = document.getElementById('current-user-email');
            
            if (userAvatar) {
                if (this.currentUser.photoURL) {
                    userAvatar.innerHTML = `<img src="${this.currentUser.photoURL}" alt="Profile" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`;
                } else {
                    userAvatar.innerHTML = `<i class="fas fa-user-circle"></i>`;
                    userAvatar.style.color = 'var(--primary-color)';
                }
            }
            
            if (currentUserName) currentUserName.textContent = this.currentUser.name;
            if (currentUserEmail) currentUserEmail.textContent = this.currentUser.email;
            
            // Update provider badge
            const providerBadge = document.querySelector('.provider-badge');
            if (providerBadge) {
                const providerIcons = {
                    'google.com': 'fab fa-google',
                    'github.com': 'fab fa-github',
                    'email': 'fas fa-envelope',
                    'demo': 'fas fa-user'
                };
                const icon = providerIcons[this.currentUser.provider] || 'fas fa-user';
                providerBadge.innerHTML = `<i class="${icon}"></i>`;
            }
        }
    }

    async handleLogout() {
        if (!this.auth) {
            // Demo mode logout
            this.currentUser = null;
            this.authToken = null;
            localStorage.removeItem('dna_demo_user');
            localStorage.removeItem('dna_demo_token');
            localStorage.removeItem('dna_remember_user');
            this.showNotification('Successfully logged out (demo mode)', 'success');
            this.showAuthModal();
            return;
        }

        try {
            await window.signOut(this.auth);
            this.currentUser = null;
            this.authToken = null;
            localStorage.removeItem('dna_remember_user');
            this.showNotification('Successfully logged out', 'success');

        } catch (error) {
            console.error('Logout error:', error);
            this.showNotification('Logout failed: ' + error.message, 'error');
        }
    }

    showUserProfile() {
        if (!this.currentUser) {
            this.showNotification('No user logged in', 'warning');
            return;
        }

        // Create a simple user profile modal
        const profileModal = document.createElement('div');
        profileModal.className = 'modal active';
        profileModal.id = 'user-profile-modal';
        profileModal.innerHTML = `
            <div class="modal-content" style="max-width: 500px; margin: 2rem auto; background: var(--bg-secondary); border-radius: var(--radius-xl); padding: 2rem;">
                <div class="modal-header" style="text-align: center; margin-bottom: 2rem;">
                    <h2 style="color: var(--text-primary); margin-bottom: 0.5rem;">User Profile</h2>
                    <button onclick="closeUserProfile()" style="position: absolute; top: 1rem; right: 1rem; background: none; border: none; color: var(--text-secondary); font-size: 1.5rem; cursor: pointer;">×</button>
                </div>
                
                <div class="profile-content" style="text-align: center;">
                    <div class="profile-avatar" style="width: 80px; height: 80px; margin: 0 auto 1rem; background: var(--primary-color); border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-size: 2rem; font-weight: bold;">
                        ${this.currentUser.photoURL ? 
                            `<img src="${this.currentUser.photoURL}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">` : 
                            this.currentUser.name.charAt(0).toUpperCase()
                        }
                    </div>
                    
                    <h3 style="color: var(--text-primary); margin-bottom: 0.5rem;">${this.currentUser.name}</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 1rem;">${this.currentUser.email}</p>
                    
                    <div class="profile-details" style="background: var(--bg-tertiary); padding: 1rem; border-radius: var(--radius-lg); margin: 1rem 0; text-align: left;">
                        <div style="margin-bottom: 0.5rem;"><strong>User ID:</strong> ${this.currentUser.uid}</div>
                        <div style="margin-bottom: 0.5rem;"><strong>Provider:</strong> ${this.currentUser.provider}</div>
                        ${this.currentUser.role ? `<div><strong>Role:</strong> ${this.currentUser.role}</div>` : ''}
                    </div>
                    
                    <div class="profile-actions" style="display: flex; gap: 1rem; justify-content: center; margin-top: 2rem;">
                        <button onclick="closeUserProfile()" class="btn btn-secondary">Close</button>
                        <button onclick="logout()" class="btn btn-danger">Logout</button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(profileModal);
    }

    async simulateApiCall() {
        return new Promise(resolve => setTimeout(resolve, 1500));
    }

    async handleDemoLogin(email, password, rememberMe) {
        const loginBtn = document.querySelector('#login-form-element .btn-primary');
        this.setButtonLoading(loginBtn, true);

        try {
            await this.simulateApiCall();
            
            const uid = 'demo_' + Date.now();
            this.currentUser = {
                uid: uid,
                email: email,
                name: email.split('@')[0],
                photoURL: null,
                provider: 'demo'
            };
            
            // Set a demo auth token in the format expected by the API
            this.authToken = 'sim_token_' + uid;

            if (rememberMe) {
                localStorage.setItem('dna_demo_user', JSON.stringify(this.currentUser));
                localStorage.setItem('dna_demo_token', this.authToken);
            }

            this.showNotification('Demo login successful! (Firebase not configured)', 'success');
            this.hideAuthModal();
            this.showMainApp();

        } catch (error) {
            this.showNotification('Demo login failed', 'error');
        } finally {
            this.setButtonLoading(loginBtn, false);
        }
    }

    async handleDemoRegister(name, email, role, password) {
        const registerBtn = document.querySelector('#register-form-element .btn-primary');
        this.setButtonLoading(registerBtn, true);

        try {
            await this.simulateApiCall();
            
            const uid = 'demo_' + Date.now();
            this.currentUser = {
                uid: uid,
                email: email,
                name: name,
                photoURL: null,
                provider: 'demo',
                role: role
            };
            
            // Set a demo auth token in the format expected by the API
            this.authToken = 'sim_token_' + uid;

            this.showNotification('Demo registration successful! (Firebase not configured)', 'success');
            this.hideAuthModal();
            this.showMainApp();

        } catch (error) {
            this.showNotification('Demo registration failed', 'error');
        } finally {
            this.setButtonLoading(registerBtn, false);
        }
    }

    async loadSamples() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/dna/samples`, {
                headers: this.getAuthHeaders()
            });
            
            if (response.ok) {
                const data = await response.json();
                this.renderSamples(data.samples || []);
            } else {
                throw new Error('API not available');
            }
        } catch (error) {

            this.renderSamples(this.getDemoSamples());
        }
    }

    async loadNFTs() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/nft/tokens`, {
                headers: this.getAuthHeaders()
            });
            
            if (response.ok) {
                const data = await response.json();
                this.renderNFTs(data.nfts || []);
            } else {
                throw new Error('API not available');
            }
        } catch (error) {

            this.renderNFTs([]);
        }
    }

    async loadAccessRequests() {
        try {
            const [pendingResponse, myResponse] = await Promise.all([
                fetch(`${this.apiBaseUrl}/access/requests/pending`, {
                    headers: this.getAuthHeaders()
                }),
                fetch(`${this.apiBaseUrl}/access/requests/my`, {
                    headers: this.getAuthHeaders()
                })
            ]);
            
            if (pendingResponse.ok && myResponse.ok) {
                const pendingData = await pendingResponse.json();
                const myData = await myResponse.json();
                this.renderAccessRequests(pendingData.requests || [], myData.requests || []);
            } else {
                throw new Error('API not available');
            }
        } catch (error) {

            const demoData = this.getDemoAccessRequests();
            this.renderAccessRequests(demoData.pending, demoData.my);
        }
    }

    async loadZKProofs() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/zkp/proofs`, {
                headers: this.getAuthHeaders()
            });
            
            if (response.ok) {
                const data = await response.json();
                this.renderZKProofs(data.proofs || []);
            } else {
                throw new Error('API not available');
            }
        } catch (error) {

            this.renderZKProofs(this.getDemoZKProofs());
        }
    }

    getAuthHeaders() {
        const headers = {
            'Content-Type': 'application/json'
        };
        
        if (this.authToken) {
            headers['Authorization'] = `Bearer ${this.authToken}`;
        }
        
        return headers;
    }

    renderSamples(samples) {
        const container = document.getElementById('samples-grid');
        if (!container) return;
        
        if (samples.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-vial"></i>
                    <h3>No DNA Samples</h3>
                    <p>Upload your first DNA sample to get started</p>
                    <button class="btn btn-primary" onclick="showUploadModal()">
                        <i class="fas fa-upload"></i> Upload Sample
                    </button>
                </div>
            `;
            return;
        }
        
        container.innerHTML = samples.map(sample => `
            <div class="sample-card">
                <div class="card-header">
                    <h3>${sample.sample_id}</h3>
                    <span class="status-badge status-${sample.status || 'active'}">${sample.status || 'Active'}</span>
                </div>
                <div class="card-content">
                    <div class="sample-info">
                        <div class="info-item">
                            <i class="fas fa-calendar"></i>
                            <span>Created: ${new Date(sample.created_at * 1000 || Date.now()).toLocaleDateString()}</span>
                        </div>
                        <div class="info-item">
                            <i class="fas fa-fingerprint"></i>
                            <span>Hash: ${sample.file_hash ? sample.file_hash.substring(0, 16) + '...' : 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <i class="fas fa-tag"></i>
                            <span>Type: ${sample.metadata?.sample_type || 'Unknown'}</span>
                        </div>
                    </div>
                </div>
                <div class="card-actions">
                    <button class="btn btn-secondary btn-sm" onclick="viewSampleDetails('${sample.sample_id}')">
                        <i class="fas fa-eye"></i> View
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadSample('${sample.sample_id}')">
                        <i class="fas fa-download"></i> Download
                    </button>
                </div>
            </div>
        `).join('');
    }

    renderNFTs(nfts) {
        const container = document.getElementById('nfts-grid');
        if (!container) return;
        
        if (nfts.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-certificate"></i>
                    <h3>No NFTs</h3>
                    <p>Mint your first NFT for DNA ownership</p>
                    <button class="btn btn-primary" onclick="showMintModal()">
                        <i class="fas fa-plus"></i> Mint NFT
                    </button>
                </div>
            `;
            return;
        }
        
        container.innerHTML = nfts.map(nft => `
            <div class="nft-card">
                <div class="card-header">
                    <h3>${nft.token_id}</h3>
                    <span class="nft-badge">NFT</span>
                </div>
                <div class="card-content">
                    <div class="nft-info">
                        <div class="info-item">
                            <i class="fas fa-vial"></i>
                            <span>Sample: ${nft.sample_id}</span>
                        </div>
                        <div class="info-item">
                            <i class="fas fa-calendar"></i>
                            <span>Minted: ${new Date(nft.mint_timestamp * 1000 || Date.now()).toLocaleDateString()}</span>
                        </div>
                        <div class="info-item">
                            <i class="fas fa-user"></i>
                            <span>Owner: ${nft.owner === this.currentUser?.uid ? 'You' : nft.owner}</span>
                        </div>
                    </div>
                </div>
                <div class="card-actions">
                    <button class="btn btn-secondary btn-sm" onclick="viewNFTDetails('${nft.token_id}')">
                        <i class="fas fa-eye"></i> View
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="transferNFT('${nft.token_id}')">
                        <i class="fas fa-exchange-alt"></i> Transfer
                    </button>
                </div>
            </div>
        `).join('');
    }

    renderAccessRequests(pendingRequests, myRequests) {
        // Render pending requests (for my samples)
        const pendingContainer = document.getElementById('pending-requests-list');
        if (pendingContainer) {
            if (pendingRequests.length === 0) {
                pendingContainer.innerHTML = `
                    <div class="empty-state-small">
                        <i class="fas fa-inbox"></i>
                        <p>No pending requests</p>
                    </div>
                `;
            } else {
                pendingContainer.innerHTML = pendingRequests.map(request => `
                    <div class="request-card">
                        <div class="request-header">
                            <h4>Request for ${request.sample_id}</h4>
                            <span class="status-badge status-pending">Pending</span>
                        </div>
                        <div class="request-content">
                            <p><strong>From:</strong> ${request.requester_email || request.requester}</p>
                            <p><strong>Purpose:</strong> ${request.purpose}</p>
                            <p><strong>Duration:</strong> ${request.expiry_hours} hours</p>
                            <p><strong>Requested:</strong> ${new Date(request.request_timestamp * 1000 || Date.now()).toLocaleDateString()}</p>
                            <p style="color: var(--primary-color); font-size: 0.9em; margin-top: 0.5rem;">
                                <i class="fas fa-info-circle"></i> You own this sample - you can approve or deny this request
                            </p>
                        </div>
                        <div class="request-actions">
                            <button class="btn btn-success btn-sm" onclick="approveRequest('${request.request_id}')">
                                <i class="fas fa-check"></i> Approve
                            </button>
                            <button class="btn btn-danger btn-sm" onclick="denyRequest('${request.request_id}')">
                                <i class="fas fa-times"></i> Deny
                            </button>
                        </div>
                    </div>
                `).join('');
            }
        }
        
        // Render my requests
        const myContainer = document.getElementById('my-requests-list');
        if (myContainer) {
            if (myRequests.length === 0) {
                myContainer.innerHTML = `
                    <div class="empty-state-small">
                        <i class="fas fa-paper-plane"></i>
                        <p>No access requests made</p>
                    </div>
                `;
            } else {
                myContainer.innerHTML = myRequests.map(request => `
                    <div class="request-card">
                        <div class="request-header">
                            <h4>Request for ${request.sample_id}</h4>
                            <span class="status-badge status-${request.status || 'pending'}">${request.status || 'Pending'}</span>
                        </div>
                        <div class="request-content">
                            <p><strong>Purpose:</strong> ${request.purpose}</p>
                            <p><strong>Duration:</strong> ${request.expiry_hours} hours</p>
                            <p><strong>Requested:</strong> ${new Date(request.request_timestamp * 1000 || Date.now()).toLocaleDateString()}</p>
                        </div>
                    </div>
                `).join('');
            }
        }
    }

    renderZKProofs(proofs) {
        const container = document.getElementById('user-proofs-list');
        if (!container) return;
        
        if (proofs.length === 0) {
            container.innerHTML = `
                <div class="empty-state-small">
                    <i class="fas fa-shield-alt"></i>
                    <p>No proofs generated</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = proofs.map(proof => `
            <div class="proof-card">
                <div class="proof-header">
                    <h4>Proof ${proof.proof_id}</h4>
                    <span class="status-badge status-${proof.verified ? 'verified' : 'pending'}">
                        ${proof.verified ? 'Verified' : 'Pending'}
                    </span>
                </div>
                <div class="proof-content">
                    <p><strong>Circuit:</strong> ${proof.circuit_type}</p>
                    <p><strong>Sample:</strong> ${proof.sample_id}</p>
                    <p><strong>Generated:</strong> ${new Date(proof.created_at * 1000 || Date.now()).toLocaleDateString()}</p>
                </div>
                <div class="proof-actions">
                    <button class="btn btn-secondary btn-sm" onclick="viewProofDetails('${proof.proof_id}')">
                        <i class="fas fa-eye"></i> View
                    </button>
                </div>
            </div>
        `).join('');
    }

    async loadRecentActivity() {
        const container = document.getElementById('recent-activity');
        if (!container) return;
        
        try {
            const response = await fetch(`${this.apiBaseUrl}/dashboard/activity`, {
                headers: this.getAuthHeaders()
            });
            
            if (response.ok) {
                const data = await response.json();
                const activities = data.activities || [];
                
                if (activities.length > 0) {
                    container.innerHTML = activities.map(activity => `
                        <div class="activity-item">
                            <div class="activity-icon">
                                <i class="${activity.icon}"></i>
                            </div>
                            <div class="activity-content">
                                <p>${activity.message}</p>
                                <span class="activity-time">${activity.time}</span>
                            </div>
                        </div>
                    `).join('');
                } else {
                    container.innerHTML = `
                        <div class="activity-item">
                            <div class="activity-icon">
                                <i class="fas fa-info-circle"></i>
                            </div>
                            <div class="activity-content">
                                <p>No recent activity</p>
                                <span class="activity-time">Start by uploading a DNA sample</span>
                            </div>
                        </div>
                    `;
                }
            } else {
                throw new Error('Activity API not available');
            }
        } catch (error) {

            container.innerHTML = `
                <div class="activity-item">
                    <div class="activity-icon">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <div class="activity-content">
                        <p>Unable to load recent activity</p>
                        <span class="activity-time">Check your connection</span>
                    </div>
                </div>
            `;
        }
    }

    setupTabNavigation() {
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tabName = e.target.closest('.nav-btn').dataset.tab;
                this.switchTab(tabName);
            });
        });
    }

    switchTab(tabName) {
        // Update nav buttons
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        // Update tab content
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');
    }

    getDemoSamples() {
        return [
            {
                sample_id: 'DNA_DEMO_001',
                owner_uid: this.currentUser?.uid,
                file_hash: 'a1b2c3d4e5f6...',
                status: 'active',
                created_at: Date.now() / 1000 - 86400,
                metadata: { sample_type: 'saliva', patient_id: 'PATIENT_001' }
            },
            {
                sample_id: 'DNA_DEMO_002',
                owner_uid: this.currentUser?.uid,
                file_hash: 'f6e5d4c3b2a1...',
                status: 'active',
                created_at: Date.now() / 1000 - 172800,
                metadata: { sample_type: 'blood', patient_id: 'PATIENT_002' }
            }
        ];
    }



    getDemoAccessRequests() {
        return {
            pending: [
                {
                    request_id: 'REQ_DEMO_001',
                    sample_id: 'DNA_DEMO_001',
                    requester: 'researcher@example.com',
                    requester_email: 'researcher@example.com',
                    purpose: 'Genetic research for rare disease analysis',
                    expiry_hours: 72,
                    request_timestamp: Date.now() / 1000 - 3600,
                    status: 'pending'
                }
            ],
            my: [
                {
                    request_id: 'REQ_DEMO_002',
                    sample_id: 'DNA_OTHER_001',
                    purpose: 'Medical diagnosis research',
                    expiry_hours: 48,
                    request_timestamp: Date.now() / 1000 - 7200,
                    status: 'approved'
                }
            ]
        };
    }

    getDemoZKProofs() {
        return [
            {
                proof_id: 'PROOF_DEMO_001',
                circuit_type: 'access_permission',
                sample_id: 'DNA_DEMO_001',
                verified: true,
                created_at: Date.now() / 1000 - 3600
            },
            {
                proof_id: 'PROOF_DEMO_002',
                circuit_type: 'identity_verification',
                sample_id: 'DNA_DEMO_002',
                verified: true,
                created_at: Date.now() / 1000 - 7200
            }
        ];
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${this.getNotificationIcon(type)}"></i>
                <span>${message}</span>
            </div>
        `;

        // Add to page
        document.body.appendChild(notification);

        // Show notification
        setTimeout(() => notification.classList.add('show'), 100);

        // Remove notification
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, 4000);
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    setupEventListeners() {
        // Modal close events
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                this.closeModal(e.target.id);
            }
        });
    }

    showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('active');
        }
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('active');
        }
    }
}

// Password toggle functionality
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const toggle = input.parentElement.querySelector('.password-toggle i');
    
    if (input.type === 'password') {
        input.type = 'text';
        toggle.classList.remove('fa-eye');
        toggle.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        toggle.classList.remove('fa-eye-slash');
        toggle.classList.add('fa-eye');
    }
}

// Global app instance
let app;

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    app = new DNABlockchainApp();
});

// Global functions for HTML onclick handlers
function logout() {
    if (app && app.handleLogout) {
        app.handleLogout();
    } else {

    }
}

function showUserProfile() {
    if (app && app.showUserProfile) {
        app.showUserProfile();
    } else {
        // Fallback: show user info in notification
        if (app && app.currentUser) {
            app.showNotification(`User: ${app.currentUser.name} (${app.currentUser.email})`, 'info');
        } else {
            app.showNotification('No user profile available', 'warning');
        }
    }
}

// Additional global functions that might be called from HTML
function showUploadModal() {
    if (app && app.showModal) {
        app.showModal('upload-modal');
    }
}

async function showMintModal() {
    if (app && app.showModal) {
        app.showModal('mint-modal');
        // Populate sample dropdown
        await populateSampleDropdown();
    }
}

async function populateSampleDropdown() {
    if (!app) return;
    
    const dropdown = document.getElementById('nft-sample-id');
    if (!dropdown) return;
    
    try {
        const response = await fetch(`${app.apiBaseUrl}/dna/samples`, {
            headers: app.getAuthHeaders()
        });
        
        if (response.ok) {
            const data = await response.json();
            const samples = data.samples || [];
            
            dropdown.innerHTML = '<option value="">Select a sample...</option>';
            samples.forEach(sample => {
                const option = document.createElement('option');
                option.value = sample.sample_id;
                option.textContent = `${sample.sample_id} (${sample.metadata?.sample_type || 'Unknown'})`;
                dropdown.appendChild(option);
            });
        } else {
            // Use demo data
            const demoSamples = app.getDemoSamples();
            dropdown.innerHTML = '<option value="">Select a sample...</option>';
            demoSamples.forEach(sample => {
                const option = document.createElement('option');
                option.value = sample.sample_id;
                option.textContent = `${sample.sample_id} (${sample.metadata?.sample_type || 'Unknown'})`;
                dropdown.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Failed to load samples for dropdown:', error);
    }
}

function showAccessRequestModal() {
    if (app && app.showModal) {
        app.showModal('access-request-modal');
    }
}

function closeModal(modalId) {
    if (app && app.closeModal) {
        app.closeModal(modalId);
    }
}

function closeUserProfile() {
    const profileModal = document.getElementById('user-profile-modal');
    if (profileModal) {
        profileModal.remove();
    }
}

// Additional global functions for HTML onclick handlers
async function viewSampleDetails(sampleId) {
    if (!app) return;
    
    try {
        const response = await fetch(`${app.apiBaseUrl}/dna/sample/${sampleId}`, {
            headers: app.getAuthHeaders()
        });
        
        let sampleData;
        if (response.ok) {
            const result = await response.json();
            sampleData = result.sample;
        } else {
            // Use demo data
            const demoSamples = app.getDemoSamples();
            sampleData = demoSamples.find(s => s.sample_id === sampleId);
        }
        
        if (sampleData) {
            showSampleDetailsModal(sampleData);
        } else {
            app.showNotification('Sample not found', 'error');
        }
        
    } catch (error) {
        console.error('Failed to load sample details:', error);
        app.showNotification('Failed to load sample details', 'error');
    }
}

function showSampleDetailsModal(sample) {
    const modal = document.getElementById('sample-details-modal');
    const content = document.getElementById('sample-details-content');
    
    if (!modal || !content) return;
    
    content.innerHTML = `
        <div class="sample-details">
            <div class="detail-section">
                <h4>Basic Information</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <label>Sample ID:</label>
                        <span>${sample.sample_id}</span>
                    </div>
                    <div class="detail-item">
                        <label>Owner:</label>
                        <span>${sample.owner_uid === app.currentUser?.uid ? 'You' : sample.owner_uid}</span>
                    </div>
                    <div class="detail-item">
                        <label>Status:</label>
                        <span class="status-badge status-${sample.status || 'active'}">${sample.status || 'Active'}</span>
                    </div>
                    <div class="detail-item">
                        <label>Created:</label>
                        <span>${new Date(sample.created_at * 1000 || Date.now()).toLocaleString()}</span>
                    </div>
                </div>
            </div>
            
            <div class="detail-section">
                <h4>File Information</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <label>File Hash:</label>
                        <span class="hash-display">${sample.file_hash || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <label>Sample Type:</label>
                        <span>${sample.metadata?.sample_type || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <label>Patient ID:</label>
                        <span>${sample.metadata?.patient_id || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <label>Collection Date:</label>
                        <span>${sample.metadata?.collection_date || 'N/A'}</span>
                    </div>
                </div>
            </div>
            
            ${sample.metadata?.notes ? `
            <div class="detail-section">
                <h4>Notes</h4>
                <p>${sample.metadata.notes}</p>
            </div>
            ` : ''}
        </div>
    `;
    
    // Set download button sample ID
    const downloadBtn = document.getElementById('download-sample-btn');
    if (downloadBtn) {
        downloadBtn.onclick = () => downloadSample(sample.sample_id);
    }
    
    modal.classList.add('active');
}

async function downloadSample(sampleId) {
    if (!app) return;
    
    const password = prompt('Enter decryption password:');
    if (!password) return;
    
    try {
        app.showNotification(`Downloading sample: ${sampleId}`, 'info');
        
        const response = await fetch(`${app.apiBaseUrl}/dna/download/${sampleId}`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify({ password: password })
        });
        
        if (response.ok) {
            const result = await response.json();
            
            // Convert base64 to blob and download
            const binaryData = atob(result.file_data);
            const bytes = new Uint8Array(binaryData.length);
            for (let i = 0; i < binaryData.length; i++) {
                bytes[i] = binaryData.charCodeAt(i);
            }
            
            const blob = new Blob([bytes], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `${sampleId}_decrypted.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            app.showNotification('Sample downloaded successfully!', 'success');
        } else {
            const error = await response.json();
            app.showNotification(`Download failed: ${error.detail || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Download error:', error);
        app.showNotification(`Download failed: ${error.message}`, 'error');
    }
}

function viewNFTDetails(tokenId) {
    if (app) {
        app.showNotification(`Viewing NFT details: ${tokenId}`, 'info');
        // TODO: Implement NFT details modal
    }
}

function transferNFT(tokenId) {
    if (app) {
        const recipient = prompt('Enter recipient email or UID:');
        if (recipient) {
            app.showNotification(`Transferring NFT ${tokenId} to ${recipient}`, 'info');
            // TODO: Implement NFT transfer
        }
    }
}

async function approveRequest(requestId) {
    if (!app) return;
    
    const reason = prompt('Enter approval reason (optional):') || 'Approved';
    
    try {
        const approvalData = {
            request_id: requestId,
            action: 'approve',
            reason: reason
        };
        
        app.showNotification(`Approving request: ${requestId}`, 'info');
        
        const response = await fetch(`${app.apiBaseUrl}/access/approve`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify(approvalData)
        });
        
        if (response.ok) {
            const result = await response.json();
            app.showNotification('Request approved successfully!', 'success');
            // Refresh access requests
            await app.loadAccessRequests();
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
        const denialData = {
            request_id: requestId,
            action: 'deny',
            reason: reason
        };
        
        app.showNotification(`Denying request: ${requestId}`, 'info');
        
        const response = await fetch(`${app.apiBaseUrl}/access/approve`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify(denialData)
        });
        
        if (response.ok) {
            const result = await response.json();
            app.showNotification('Request denied successfully!', 'warning');
            // Refresh access requests
            await app.loadAccessRequests();
        } else {
            const error = await response.json();
            app.showNotification(`Denial failed: ${error.detail || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Denial error:', error);
        app.showNotification(`Denial failed: ${error.message}`, 'error');
    }
}

function viewProofDetails(proofId) {
    if (!app) return;
    
    // Create modal immediately with proof details
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Proof Details: ${proofId}</h3>
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
            </div>
            <div class="modal-body">
                <div class="proof-details">
                    <div class="detail-row">
                        <strong>Proof ID:</strong> ${proofId}
                    </div>
                    <div class="detail-row">
                        <strong>Sample ID:</strong> DNA_004
                    </div>
                    <div class="detail-row">
                        <strong>Circuit Type:</strong> access_permission
                    </div>
                    <div class="detail-row">
                        <strong>Status:</strong> 
                        <span class="status-badge status-verified">Verified</span>
                    </div>
                    <div class="detail-row">
                        <strong>Created:</strong> ${new Date().toLocaleString()}
                    </div>
                    <div class="detail-row">
                        <strong>Simulated:</strong> Yes
                    </div>
                    <div class="detail-section">
                        <strong>Proof Structure:</strong>
                        <pre class="proof-data">{
  "commitment": "abc123def456789abcdef...",
  "challenge": "789ghi012jkl345mnopqr...",
  "response": "345mno678pqr901stuvwx...",
  "nonce": "random_nonce_123456",
  "protocol": "sigma_protocol"
}</pre>
                    </div>
                    <div class="detail-section">
                        <strong>Public Inputs:</strong>
                        <pre class="proof-data">{
  "sample_id": "DNA_004_hash_value",
  "timestamp": "${Math.floor(Date.now() / 1000)}",
  "permission_hash": "permission_hash_value"
}</pre>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">Close</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    app.showNotification('Proof details opened', 'success');
}

async function uploadSample() {
    if (!app) return;
    
    const sampleId = document.getElementById('sample-id')?.value;
    const dnaFile = document.getElementById('dna-file')?.files[0];
    const password = document.getElementById('encryption-password')?.value;
    const sampleType = document.getElementById('sample-type')?.value;
    const collectionDate = document.getElementById('collection-date')?.value;
    const patientId = document.getElementById('patient-id')?.value;
    const notes = document.getElementById('sample-notes')?.value;
    
    if (!sampleId || !dnaFile || !password) {
        app.showNotification('Please fill in all required fields', 'error');
        return;
    }
    
    try {
        // Read file as base64
        const fileData = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result.split(',')[1]); // Remove data:... prefix
            reader.onerror = reject;
            reader.readAsDataURL(dnaFile);
        });
        
        const uploadData = {
            sample_id: sampleId,
            owner: app.currentUser.uid,
            file_data: fileData,
            password: password,
            metadata: {
                sample_type: sampleType,
                collection_date: collectionDate,
                patient_id: patientId,
                notes: notes,
                filename: dnaFile.name,
                file_size: dnaFile.size
            }
        };
        
        app.showNotification('Uploading DNA sample...', 'info');
        
        const response = await fetch(`${app.apiBaseUrl}/dna/upload`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify(uploadData)
        });
        
        if (response.ok) {
            const result = await response.json();
            app.showNotification('DNA sample uploaded successfully!', 'success');
            app.closeModal('upload-modal');
            // Refresh samples list
            await app.loadSamples();
        } else {
            const error = await response.json();
            app.showNotification(`Upload failed: ${error.detail || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Upload error:', error);
        app.showNotification(`Upload failed: ${error.message}`, 'error');
    }
}

async function mintNFT() {
    if (!app) return;
    
    const tokenId = document.getElementById('token-id')?.value;
    const sampleId = document.getElementById('nft-sample-id')?.value;
    const metadataUri = document.getElementById('metadata-uri')?.value;
    
    if (!tokenId || !sampleId) {
        app.showNotification('Please fill in all required fields', 'error');
        return;
    }
    
    try {
        const mintData = {
            token_id: tokenId,
            sample_id: sampleId,
            metadata_uri: metadataUri || null
        };
        
        app.showNotification('Minting NFT...', 'info');
        
        const response = await fetch(`${app.apiBaseUrl}/nft/mint`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify(mintData)
        });
        
        if (response.ok) {
            const result = await response.json();
            app.showNotification('NFT minted successfully!', 'success');
            app.closeModal('mint-modal');
            // Refresh NFTs list
            await app.loadNFTs();
        } else {
            const error = await response.json();
            app.showNotification(`Minting failed: ${error.detail || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Minting error:', error);
        app.showNotification(`Minting failed: ${error.message}`, 'error');
    }
}

async function requestAccess() {
    if (!app) return;
    
    const sampleId = document.getElementById('access-sample-id')?.value;
    const purpose = document.getElementById('access-purpose')?.value;
    const duration = document.getElementById('access-duration')?.value;
    
    if (!sampleId || !purpose || !duration) {
        app.showNotification('Please fill in all required fields', 'error');
        return;
    }
    
    try {
        const requestData = {
            sample_id: sampleId,
            purpose: purpose,
            expiry_hours: parseInt(duration)
        };
        
        app.showNotification('Submitting access request...', 'info');
        
        const response = await fetch(`${app.apiBaseUrl}/access/request`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify(requestData)
        });
        
        if (response.ok) {
            const result = await response.json();
            app.showNotification('Access request submitted successfully!', 'success');
            app.closeModal('access-request-modal');
            // Refresh access requests
            await app.loadAccessRequests();
        } else {
            const error = await response.json();
            app.showNotification(`Request failed: ${error.detail || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Request error:', error);
        app.showNotification(`Request failed: ${error.message}`, 'error');
    }
}


async function generateZKProof() {
    if (!app) return;
    
    const circuitType = document.getElementById('circuit-type')?.value || 'access_permission';
    const sampleId = document.getElementById('zkp-sample-id')?.value;
    const userSecret = document.getElementById('zkp-user-secret')?.value;
    
    if (!sampleId || !userSecret) {
        app.showNotification('Please fill in all fields', 'warning');
        return;
    }
    
    if (userSecret.length < 8) {
        app.showNotification('User secret must be at least 8 characters long', 'warning');
        return;
    }
    
    try {
        // Debug logging
        console.log('ZKP Request Data:', {
            circuit_type: circuitType,
            sample_id: sampleId,
            user_secret: userSecret ? `${userSecret.length} chars` : 'empty'
        });
        
        app.showNotification(`Generating ${circuitType} proof for ${sampleId}`, 'info');
        
        const requestBody = {
            circuit_type: circuitType,
            sample_id: sampleId,
            user_secret: userSecret
        };
        
        console.log('Sending ZKP request:', requestBody);
        
        const response = await fetch(`${app.apiBaseUrl}/zkp/generate`, {
            method: 'POST',
            headers: app.getAuthHeaders(),
            body: JSON.stringify(requestBody)
        });
        
        if (response.ok) {
            const result = await response.json();
            if (result.simulated) {
                app.showNotification('✅ Zero-knowledge proof generated successfully! (Simulation mode)', 'success');
            } else {
                app.showNotification('✅ Zero-knowledge proof generated successfully!', 'success');
            }
            // Clear form
            document.getElementById('zkp-sample-id').value = '';
            document.getElementById('zkp-user-secret').value = '';
            // Refresh proofs list
            await app.loadZKProofs();
        } else {
            const error = await response.json();
            let errorMessage = error.detail || 'Unknown error';
            
            // Provide helpful guidance for common errors
            if (errorMessage.includes('at least 8 characters')) {
                errorMessage += '\n\n💡 Tip: Your secret must be at least 8 characters long for security.';
            } else if (errorMessage.includes('Sample not found')) {
                errorMessage += '\n\n💡 Tip: Make sure you own this sample and it exists in the system.';
            } else if (errorMessage.includes('only generate ZKP for your own samples')) {
                errorMessage += '\n\n💡 Tip: You can only create proofs for samples you uploaded.';
            }
            
            app.showNotification(`Proof generation failed: ${errorMessage}`, 'error');
        }
        
    } catch (error) {
        console.error('ZKP generation error:', error);
        app.showNotification(`Proof generation failed: ${error.message}`, 'error');
    }
}


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