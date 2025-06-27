# Cryple

A **secure, client-side encryption application** for storing sensitive key-value data with BIP39 seed phrase authentication and deterministic user identification. Cryple provides complete control over your sensitive data with zero-knowledge architecture.

---

## 🔐 Core Concept

**Cryple** implements a **zero-knowledge encryption system** where:

- **All encryption happens client-side** - Server never sees plaintext data
- **BIP39 seed phrases** generate deterministic user identities
- **Password-based local storage** protects seed phrases on device
- **Backend stores only encrypted data** with no decryption capability
- **Independent solution** - No external wallet dependencies required

### Security Model

```
User Password → Encrypts Seed Phrase (localStorage)
     ↓
Seed Phrase → Derives User Address (deterministic ID)
     ↓
Seed Phrase → Derives Encryption Key (for data)
     ↓
Encryption Key → Encrypts all user data (sent to backend)
```

---

## 🚀 Current Implementation

### ✅ Implemented Features

1. **BIP39 Seed Phrase System**

   - Proper 12-word mnemonic generation using 128-bit entropy
   - Seed phrase validation and import functionality
   - Deterministic user address derivation (SHA-256 hash)

2. **Client-Side Encryption**

   - AES-GCM encryption with unique IVs per operation
   - Scrypt-based key derivation from seed phrases
   - Separate encryption for keys and values
   - Password-based local storage encryption (PBKDF2 + random salt)

3. **Authentication Flow**

   - **Registration**: Generate seed phrase → encrypt with password → store locally
   - **Login**: Password-only authentication (decrypts stored seed phrase)
   - **Import**: Existing seed phrase recovery with new password
   - **Session Management**: 8-hour sessions with automatic expiry

4. **Data Management**

   - Encrypt key-value pairs client-side before transmission
   - Backend API integration with configurable BASE_API_URL
   - Real-time data loading and encryption testing
   - Persistent encrypted seed phrase storage (survives logout)

5. **Security Features**

   - Strong cryptographic parameters (scrypt N=65536)
   - Unique salts prevent rainbow table attacks

### 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │     Backend      │    │    Database     │
│   (Next.js)     │    │      (Go)        │    │   (Postgres)    │
├─────────────────┤    ├──────────────────┤    ├─────────────────┤
│ • BIP39 seeds   │    │ • User routes    │    │ • user_address  │
│ • AES-GCM       │◄──►│ • Data storage   │◄──►│ • encrypted_key │
│ • Key derivation│    │ • CRUD ops       │    │ • encrypted_val │
│ • Password auth │    │ • No decryption  │    │ • iv + key_iv   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### 📦 Dependencies

```json
{
  "bip39": "^3.1.0", // BIP39 mnemonic generation/validation
  "@noble/hashes": "^1.8.0", // Scrypt, SHA-256 cryptographic functions
  "next": "15.3.4", // React framework
  "react": "^19.0.0", // UI library
  "tailwindcss": "^4" // Styling
}
```

---

## 🔄 User Flow

### Registration Flow

1. User creates password
2. System generates 12-word BIP39 seed phrase
3. Seed phrase encrypted with password (PBKDF2 + random salt)
4. Encrypted seed phrase stored in localStorage
5. User address derived deterministically from seed phrase
6. User shown seed phrase once for backup
7. Backend authentication established

### Login Flow

1. User enters password
2. System attempts to decrypt stored seed phrase
3. If successful → derive user address and encryption key
4. If failed → show "Account not found or incorrect password"
5. Backend authentication with derived credentials
6. Session established (8-hour expiry)

### Data Operations

1. **Store**: Encrypt key+value separately → send to backend
2. **Retrieve**: Fetch encrypted data → decrypt client-side
3. **All operations** use encryption key derived from seed phrase

---

## 🛠️ Getting Started

### Environment Setup

1. Copy the example environment file:

```bash
cp .env.example .env.local
```

2. Configure your environment variables in `.env.local`:

```bash
NEXT_PUBLIC_BASE_API_URL=http://localhost:8080  # Your backend API URL
```

### Development Server

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to access Cryple.

### Backend Requirements

Your Go backend should implement these endpoints:

- `POST /sign-in` - User authentication
- `POST /values` - Store encrypted key-value pairs
- `GET /values?user_address=<address>` - Retrieve user's encrypted data

---

## 🔒 Security Features

### Cryptographic Specifications

- **Seed Generation**: BIP39 with 128-bit entropy (12 words)
- **Key Derivation**: Scrypt (N=65536, r=8, p=1) for encryption keys
- **Password Storage**: PBKDF2 (100,000 iterations) with random salt
- **Symmetric Encryption**: AES-GCM with unique 96-bit IVs
- **Hashing**: SHA-256 for user address derivation

### Privacy Protections

- **Zero-knowledge server**: Backend cannot decrypt any data
- **No tracking**: User IDs are cryptographically derived
- **Local-first**: All sensitive operations happen client-side
- **No information leakage**: Login doesn't reveal account existence

### Attack Resistance

- **Server breach**: Only encrypted data exposed
- **Pattern analysis**: Unique IVs prevent identical ciphertext
- **Rainbow tables**: App-specific salts and random user salts
- **Brute force**: Strong scrypt parameters increase computation cost

---

## 🧪 Development Notes

### Testing Encryption

The app includes internal encryption verification that automatically runs when loading user data:

- Key derivation from seed phrase
- AES-GCM encryption/decryption functionality
- Key-value pair handling validation
- Backend communication testing

This verification happens behind the scenes to ensure the cryptographic system is working properly before processing user data.

### Code Quality

- **No console.log statements** in production code
- **Comprehensive error handling** for all crypto operations
- **Type safety** with TypeScript throughout
- **Secure defaults** for all cryptographic parameters

---

## 🚀 Future Enhancements

1. **13th Word Security Model** (next priority)
2. **Web3 Wallet Integration** (MetaMask, WalletConnect)
3. **Multi-device Sync** (encrypted cloud backup)
4. **Audit Trail** (encrypted operation logs)
5. **Mobile App** (React Native with same crypto core)

---

## 📖 Additional Resources

- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [Web Crypto API Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Noble Crypto Libraries](https://github.com/paulmillr/noble-hashes)

---

**Cryple** - Secure by design, private by default. 🔐
