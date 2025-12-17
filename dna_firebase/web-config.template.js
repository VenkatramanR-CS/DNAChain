// Firebase Web Configuration Template
// Copy this file to web-config.js and replace with your actual Firebase credentials
// Get these values from Firebase Console > Project Settings > General > Your apps

const firebaseWebConfig = {
    apiKey: "YOUR_API_KEY_HERE",
    authDomain: "your-project-id.firebaseapp.com",
    projectId: "your-project-id",
    storageBucket: "your-project-id.firebasestorage.app",
    messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
    appId: "YOUR_APP_ID_HERE"
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = firebaseWebConfig;
} else {
    window.firebaseWebConfig = firebaseWebConfig;
}