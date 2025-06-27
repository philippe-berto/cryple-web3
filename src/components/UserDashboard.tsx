'use client';

import { useState, useEffect } from 'react';
import { retrieveSeedPhrase, deriveEncryptionKey, sendEncryptedDataToBackend, fetchAndDecryptDataFromBackend, testEncryptionDecryption } from '@/lib/crypto';

interface UserDashboardProps {
  userAddress: string;
  onLogout: (errorMessage?: string) => void;
}

interface KeyValuePair {
  id: string;
  key: string;
  value: string;
  createdAt: string;
}

export default function UserDashboard({ userAddress, onLogout }: UserDashboardProps) {
  const [keyValuePairs, setKeyValuePairs] = useState<KeyValuePair[]>([]);
  const [newKey, setNewKey] = useState('');
  const [newValue, setNewValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);

  useEffect(() => {
    initializeEncryptionKey();
  }, []);

  useEffect(() => {
    if (encryptionKey) {
      loadData();
    }
  }, [encryptionKey]);

  const initializeEncryptionKey = async () => {
    try {
      // We need to get the user's password to retrieve the seed phrase
      // For now, we'll prompt the user or store it securely during login
      // This is a simplified approach - in production you'd handle this more securely
      const password = sessionStorage.getItem('userPassword');
      
      if (!password) {
        setError('Please log in again to access encrypted data');
        return;
      }

      const seedPhrase = await retrieveSeedPhrase(password);
      
      if (!seedPhrase) {
        setError('Failed to retrieve seed phrase');
        return;
      }

      const key = await deriveEncryptionKey(seedPhrase);
      
      // Test encryption/decryption to make sure it works
      const testResult = await testEncryptionDecryption(key);
      
      if (!testResult) {
        // Encryption test failed - log out user and show error on login screen
        onLogout('Encryption system validation failed. Please try logging in again or contact support.');
        return;
      }
      
      setEncryptionKey(key);
    } catch (err) {
      setError('Failed to initialize encryption');
    }
  };

  const loadData = async () => {
    try {
      setLoading(true);
      setError('');
      
      if (!encryptionKey) {
        return;
      }

      // Fetch encrypted data from backend and decrypt it
      const result = await fetchAndDecryptDataFromBackend(userAddress, encryptionKey);

      if (!result.success) {
        setError(result.message || 'Failed to load data');
        return;
      }

      setKeyValuePairs(result.data || []);
    } catch (err) {
      setError('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleAddKeyValue = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKey.trim() || !newValue.trim()) return;
    
    if (!encryptionKey) {
      setError('Encryption key not available. Please refresh the page and try again.');
      return;
    }

    try {
      setLoading(true);
      setError('');

      // Send encrypted data to backend
      const result = await sendEncryptedDataToBackend(
        userAddress,
        newKey.trim(),
        newValue.trim(),
        encryptionKey
      );

      if (!result.success) {
        throw new Error(result.message || 'Failed to store data');
      }

      // Clear form fields
      setNewKey('');
      setNewValue('');
      
      // Reload data from backend to get the updated list
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add data');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteKeyValue = async (id: string) => {
    try {
      // TODO: Implement delete functionality with backend API
      // For now, we'll keep the current behavior
      const updatedPairs = keyValuePairs.filter(pair => pair.id !== id);
      setKeyValuePairs(updatedPairs);
    } catch (err) {
      setError('Failed to delete data');
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-8">
        <div className="flex justify-between items-center mb-8">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
              Your Encrypted Data
            </h2>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
              User ID: {userAddress.substring(0, 16)}...
            </p>
          </div>
          <button
            onClick={() => onLogout()}
            className="bg-red-600 hover:bg-red-700 text-white font-semibold py-2 px-4 rounded-lg transition duration-200"
          >
            Logout
          </button>
        </div>

        {/* Add new key-value pair form */}
        <div className="mb-8 bg-gray-50 dark:bg-gray-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Add New Data
          </h3>
          
          <form onSubmit={handleAddKeyValue} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="key" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Key
                </label>
                <input
                  type="text"
                  id="key"
                  value={newKey}
                  onChange={(e) => setNewKey(e.target.value)}
                  placeholder="e.g., email, password, notes"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-600 dark:text-white"
                  required
                  disabled={loading}
                />
              </div>
              
              <div>
                <label htmlFor="value" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Value
                </label>
                <input
                  type="text"
                  id="value"
                  value={newValue}
                  onChange={(e) => setNewValue(e.target.value)}
                  placeholder="Enter the value to encrypt"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-600 dark:text-white"
                  required
                  disabled={loading}
                />
              </div>
            </div>
            
            <button
              type="submit"
              disabled={loading || !newKey.trim() || !newValue.trim()}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white font-semibold py-2 px-4 rounded-lg transition duration-200"
            >
              {loading ? 'Adding...' : 'Add Data'}
            </button>
          </form>
        </div>

        {error && (
          <div className="mb-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 rounded-lg p-3">
            <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
          </div>
        )}

        {/* Display existing key-value pairs */}
        <div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Stored Data ({keyValuePairs.length} items)
          </h3>
          
          {keyValuePairs.length === 0 ? (
            <div className="text-center py-8">
              <div className="text-gray-400 dark:text-gray-500 text-4xl mb-4">🔒</div>
              <p className="text-gray-600 dark:text-gray-400">
                No data stored yet. Add your first encrypted key-value pair above.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {keyValuePairs.map((pair) => (
                <div
                  key={pair.id}
                  className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 flex justify-between items-start"
                >
                  <div className="flex-1">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
                          Key
                        </label>
                        <p className="text-sm font-mono text-gray-900 dark:text-white break-words">
                          {pair.key}
                        </p>
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
                          Value
                        </label>
                        <p className="text-sm font-mono text-gray-900 dark:text-white break-words">
                          {pair.value}
                        </p>
                      </div>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                      Added: {new Date(pair.createdAt).toLocaleString()}
                    </p>
                  </div>
                  <button
                    onClick={() => handleDeleteKeyValue(pair.id)}
                    className="ml-4 bg-red-500 hover:bg-red-600 text-white text-xs font-semibold py-1 px-2 rounded transition duration-200"
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
