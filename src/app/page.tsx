'use client';

import { useState, useEffect } from 'react';
import LoginForm from '@/components/LoginForm';
import UserDashboard from '@/components/UserDashboard';

export default function Home() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userAddress, setUserAddress] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [logoutErrorMessage, setLogoutErrorMessage] = useState<string>('');

  useEffect(() => {
    // Check if user is already logged in (has a valid session)
    const savedUserAddress = localStorage.getItem('userAddress');
    const sessionExpiry = localStorage.getItem('sessionExpiry');
    
    if (savedUserAddress && sessionExpiry) {
      const currentTime = new Date().getTime();
      if (currentTime < parseInt(sessionExpiry)) {
        setIsAuthenticated(true);
        setUserAddress(savedUserAddress);
      } else {
        // Session expired, clear storage
        localStorage.removeItem('userAddress');
        localStorage.removeItem('sessionExpiry');
      }
    }
    setLoading(false);
  }, []);

  const handleLogin = (userAddr: string) => {
    setIsAuthenticated(true);
    setUserAddress(userAddr);
    setLogoutErrorMessage(''); // Clear any previous logout error
    
    // Set session to expire in 8 hours
    const sessionExpiry = new Date().getTime() + (8 * 60 * 60 * 1000);
    localStorage.setItem('userAddress', userAddr);
    localStorage.setItem('sessionExpiry', sessionExpiry.toString());
  };

  const handleLogout = (errorMessage?: string) => {
    setIsAuthenticated(false);
    setUserAddress('');
    localStorage.removeItem('userAddress');
    localStorage.removeItem('sessionExpiry');
    // DO NOT remove encryptedSeedPhrase - it should persist for future logins
    sessionStorage.removeItem('userPassword'); // Clear stored password
    
    // Set error message if provided (from encryption failure)
    if (errorMessage) {
      setLogoutErrorMessage(errorMessage);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
        <div className="animate-pulse">
          <div className="w-8 h-8 bg-blue-500 rounded-full"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      <div className="container mx-auto px-4 py-8">
        <header className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">
            Cryple
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Secure encrypted data storage with seed phrase authentication
          </p>
        </header>

        {!isAuthenticated ? (
          <LoginForm onLogin={handleLogin} initialErrorMessage={logoutErrorMessage} />
        ) : (
          <UserDashboard userAddress={userAddress} onLogout={handleLogout} />
        )}
      </div>
    </div>
  );
}
