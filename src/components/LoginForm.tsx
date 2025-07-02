'use client';

import { useState } from 'react';
import { generateSeedPhrase, deriveUserAddress, storeSeedPhrase, retrieveSeedPhrase, validateSeedPhrase, importSeedPhrase, authenticateWithBackend, clearSessionData, verifyUserCredentials } from '@/lib/crypto';

interface LoginFormProps {
  onLogin: (userAddress: string) => void;
  initialErrorMessage?: string;
}

export default function LoginForm({ onLogin, initialErrorMessage }: LoginFormProps) {
  const [mode, setMode] = useState<'login' | 'register' | 'import'>('login');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [importSeedPhraseText, setImportSeedPhraseText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(initialErrorMessage || '');
  const [generatedSeedPhrase, setGeneratedSeedPhrase] = useState('');
  const [registrationStep, setRegistrationStep] = useState<1 | 2>(1);
  const [enteredSeedPhrase, setEnteredSeedPhrase] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (mode === 'login') {
        // Login flow - retrieve stored seed phrase and verify with backend
        const seedPhrase = await retrieveSeedPhrase(password);
        if (!seedPhrase) {
          throw new Error('Account not found or incorrect password');
        }
        
        const userAddress = await deriveUserAddress(seedPhrase);
        
        // Verify credentials with backend using /users/check
        const verifyResult = await verifyUserCredentials(userAddress, password);
        if (!verifyResult.success) {
          throw new Error(verifyResult.message || 'Login failed');
        }
        
        // Store password temporarily for encryption key derivation
        sessionStorage.setItem('userPassword', password);
        
        onLogin(userAddress);
      } else if (mode === 'import') {
        // Import existing seed phrase
        if (!validateSeedPhrase(importSeedPhraseText.trim())) {
          throw new Error('Invalid seed phrase. Please check and try again.');
        }
        if (password !== confirmPassword) {
          throw new Error('Passwords do not match');
        }
        if (password.length < 8) {
          throw new Error('Password must be at least 8 characters long');
        }

        const { userAddress } = await importSeedPhrase(importSeedPhraseText.trim(), password);
        
        // Store password temporarily for encryption key derivation
        sessionStorage.setItem('userPassword', password);
        
        onLogin(userAddress);
      } else if (mode === 'register') {
        if (registrationStep === 1) {
          // Step 1: Generate and show seed phrase (don't advance step yet)
          const newSeedPhrase = await generateSeedPhrase();
          setGeneratedSeedPhrase(newSeedPhrase);
          // Stay in step 1 to show the seed phrase
          return;
        } else {
          // Step 2: Verify seed phrase and create account
          if (!validateSeedPhrase(enteredSeedPhrase.trim())) {
            throw new Error('Invalid seed phrase. Please check and try again.');
          }
          if (enteredSeedPhrase.trim() !== generatedSeedPhrase) {
            throw new Error('Seed phrase does not match. Please enter the exact phrase shown earlier.');
          }
          if (password !== confirmPassword) {
            throw new Error('Passwords do not match');
          }
          if (password.length < 8) {
            throw new Error('Password must be at least 8 characters long');
          }

          await storeSeedPhrase(generatedSeedPhrase, password);
          
          const userAddress = await deriveUserAddress(generatedSeedPhrase);
          
          // Register with backend server
          const authResult = await authenticateWithBackend(userAddress, password);
          if (!authResult.success) {
            throw new Error(authResult.message || 'Backend registration failed');
          }
          
          // Store password temporarily for encryption key derivation
          sessionStorage.setItem('userPassword', password);
          
          onLogin(userAddress);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleBackToStep1 = () => {
    setRegistrationStep(1);
    setEnteredSeedPhrase('');
    setPassword('');
    setConfirmPassword('');
    setError('');
  };

  // Step 1 of registration: Show generated seed phrase
  if (mode === 'register' && registrationStep === 1 && generatedSeedPhrase) {
    // This is now handled inline in the main form
  }

  return (
    <div className="max-w-md mx-auto">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-8">
        <h2 className="text-2xl font-bold text-center text-gray-900 dark:text-white mb-6">
          {mode === 'login' ? 'Login' : 
           mode === 'register' ? `Create Account - Step ${registrationStep}/2` : 
           'Import Account'}
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Only show form fields when NOT displaying seed phrase in step 1 */}
          {!(mode === 'register' && registrationStep === 1 && generatedSeedPhrase) && (
            <>
              {/* Registration Step 2: Re-enter seed phrase */}
              {mode === 'register' && registrationStep === 2 && (
                <div>
                  <label htmlFor="seedPhraseVerify" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Re-enter Your Seed Phrase
                  </label>
                  <textarea
                    id="seedPhraseVerify"
                    value={enteredSeedPhrase}
                    onChange={(e) => setEnteredSeedPhrase(e.target.value)}
                    placeholder="Enter the 12-word seed phrase you just saved..."
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                    required
                    disabled={loading}
                  />
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    This confirms you've safely stored your seed phrase
                  </p>
                </div>
              )}

              {/* Import mode: Enter existing seed phrase */}
              {mode === 'import' && (
                <div>
                  <label htmlFor="seedPhrase" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Seed Phrase (12 words)
                  </label>
                  <textarea
                    id="seedPhrase"
                    value={importSeedPhraseText}
                    onChange={(e) => setImportSeedPhraseText(e.target.value)}
                    placeholder="Enter your 12-word seed phrase..."
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                    required
                    disabled={loading}
                  />
                </div>
              )}

              {/* Password field - shown for all modes except registration step 1 */}
              {!(mode === 'register' && registrationStep === 1) && (
                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Password
                  </label>
                  <input
                    type="password"
                    id="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                    required
                    disabled={loading}
                  />
                </div>
              )}

              {/* Confirm password - shown for registration step 2 and import */}
              {((mode === 'register' && registrationStep === 2) || mode === 'import') && (
                <div>
                  <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Confirm Password
                  </label>
                  <input
                    type="password"
                    id="confirmPassword"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
                    required
                    disabled={loading}
                  />
                </div>
              )}
            </>
          )}

          {/* Show seed phrase display in step 1 after generation */}
          {mode === 'register' && registrationStep === 1 && generatedSeedPhrase && (
            <div className="space-y-6">
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 rounded-lg p-4">
                <p className="text-sm text-red-800 dark:text-red-200 mb-2">
                  🔒 <strong>CRITICAL:</strong> This is your only way to recover your account!
                </p>
                <ul className="text-xs text-red-700 dark:text-red-300 list-disc list-inside space-y-1">
                  <li>Write it down on paper and store it safely</li>
                  <li>Never share it with anyone</li>
                  <li>Don't save it digitally (screenshots, files, etc.)</li>
                  <li>You'll need to enter it on the next step</li>
                </ul>
              </div>

              <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Your Seed Phrase
                </label>
                <p className="text-sm font-mono text-gray-900 dark:text-white break-words leading-relaxed">
                  {generatedSeedPhrase}
                </p>
              </div>
            </div>
          )}

          {error && (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 rounded-lg p-3">
              <p className="text-sm text-red-800 dark:text-red-200">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white font-semibold py-3 px-4 rounded-lg transition duration-200"
            onClick={mode === 'register' && registrationStep === 1 && generatedSeedPhrase ? 
              (e) => {
                e.preventDefault();
                setRegistrationStep(2);
              } : undefined}
          >
            {loading ? 'Processing...' : 
             mode === 'login' ? 'Login' : 
             mode === 'register' && registrationStep === 1 && !generatedSeedPhrase ? 'Generate Seed Phrase' :
             mode === 'register' && registrationStep === 1 && generatedSeedPhrase ? 'I\'ve Saved My Seed Phrase - Continue' :
             mode === 'register' && registrationStep === 2 ? 'Create Account' :
             'Import Account'}
          </button>

          {/* Cancel/Back button when showing seed phrase in step 1 */}
          {mode === 'register' && registrationStep === 1 && generatedSeedPhrase && (
            <button
              type="button"
              onClick={() => {
                setGeneratedSeedPhrase('');
                setError('');
              }}
              className="w-full mt-3 bg-gray-500 hover:bg-gray-600 text-white font-semibold py-2 px-4 rounded-lg transition duration-200"
            >
              Generate New Seed Phrase
            </button>
          )}
        </form>

        {/* Navigation buttons */}
        <div className="mt-6 text-center space-y-2">
          {/* Back button for registration step 2 */}
          {mode === 'register' && registrationStep === 2 && (
            <button
              onClick={handleBackToStep1}
              className="w-full mb-4 bg-gray-500 hover:bg-gray-600 text-white font-semibold py-2 px-4 rounded-lg transition duration-200"
            >
              ← Back to Seed Phrase
            </button>
          )}

          {/* Mode switcher - only show when not in registration step 2 */}
          {!(mode === 'register' && registrationStep === 2) && (
            <div className="flex justify-center space-x-4 text-sm">
              <button
                onClick={() => {
                  setMode('login');
                  setError('');
                  setPassword('');
                  setConfirmPassword('');
                  setImportSeedPhraseText('');
                  setGeneratedSeedPhrase('');
                  setRegistrationStep(1);
                  setEnteredSeedPhrase('');
                }}
                className={`${mode === 'login' ? 'text-blue-600 font-semibold' : 'text-gray-500 hover:text-blue-600'} transition-colors`}
              >
                Login
              </button>
              <button
                onClick={() => {
                  setMode('register');
                  setError('');
                  setPassword('');
                  setConfirmPassword('');
                  setImportSeedPhraseText('');
                  setGeneratedSeedPhrase('');
                  setRegistrationStep(1);
                  setEnteredSeedPhrase('');
                }}
                className={`${mode === 'register' ? 'text-blue-600 font-semibold' : 'text-gray-500 hover:text-blue-600'} transition-colors`}
              >
                Register
              </button>
              <button
                onClick={() => {
                  setMode('import');
                  setError('');
                  setPassword('');
                  setConfirmPassword('');
                  setImportSeedPhraseText('');
                  setGeneratedSeedPhrase('');
                  setRegistrationStep(1);
                  setEnteredSeedPhrase('');
                }}
                className={`${mode === 'import' ? 'text-blue-600 font-semibold' : 'text-gray-500 hover:text-blue-600'} transition-colors`}
              >
                Import
              </button>
            </div>
          )}

          <p className="text-xs text-gray-500 dark:text-gray-400">
            {mode === 'login' && "Enter your password to access your account"}
            {mode === 'register' && registrationStep === 1 && "Create a new account with a secure seed phrase"}
            {mode === 'register' && registrationStep === 2 && "Verify your seed phrase and set a password"}
            {mode === 'import' && "Recover your account using your 12-word seed phrase"}
          </p>
        </div>
      </div>
    </div>
  );
}
