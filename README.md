#  Secure Communication System with Digital Envelope & Keyed Hash MAC

A Java implementation of a secure communication system demonstrating hybrid encryption, message authentication, and key distribution using industry-standard cryptographic protocols.

## Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Technical Implementation](#-technical-implementation)
- [Project Structure](#-project-structure)
- [Installation & Setup](#-installation--setup)
- [Usage Guide](#-usage-guide)
- [Security Concepts](#-security-concepts)
- [Testing](#-testing)
- [Learning Outcomes](#-learning-outcomes)

## Overview

This project implements a complete **digital envelope** system with **keyed hash MAC** authentication, demonstrating how modern secure communication systems work. It showcases the combination of symmetric and asymmetric cryptography to achieve both security and performance.

**Key Scenario**: Sender (X) wants to send an encrypted message to Receiver (Y) with authentication guarantee.

### What This Project Demonstrates

- **Hybrid Encryption**: Combining RSA (asymmetric) and AES (symmetric) encryption
- **Message Authentication**: Keyed Hash MAC using SHA-256
- **Secure Key Distribution**: Digital envelope technique
- **Binary File Processing**: Handling large files efficiently
- **Real-world Cryptography**: Using Java's standard cryptographic APIs

## Features

### Key Generation (`KeyGen`)
- Generates 1024-bit RSA keypairs for both sender and receiver
- Creates 128-bit AES symmetric key
- Stores keys in platform-independent binary format

### Sender (`Sender`)
- Computes keyed hash MAC: `SHA256(Kxy || M || Kxy)`
- Encrypts message with AES-128
- Wraps symmetric key with recipient's RSA public key
- Handles files of any size through streaming

### Receiver (`Receiver`)
- Unwraps symmetric key using RSA private key
- Decrypts message using AES
- Verifies message authenticity via MAC comparison
- Reports authentication success/failure

## System Architecture

```
┌──────────────┐                                  ┌──────────────┐
│              │                                  │              │
│  Sender (X)  │                                  │ Receiver (Y) │
│              │                                  │              │
│  Has: Ky+    │                                  │  Has: Ky-    │
│       Kxy    │                                  │              │
└──────┬───────┘                                  └──────▲───────┘
       │                                                 │
       │  1. Compute MAC = SHA256(Kxy||M||Kxy)           │
       │  2. Encrypt message: C = AES-Enc(M, Kxy)        │
       │  3. Wrap key: K = RSA-Enc(Kxy, Ky+)             │
       │                                                 │
       └─────────────────────────────────────────────────┘
                 Transmit: {C, K, MAC}
       
       ┌─────────────────────────────────────────────────┐
       │                                                 │
       │  4. Unwrap key: Kxy = RSA-Dec(K, Ky-)           │
       │  5. Decrypt: M = AES-Dec(C, Kxy)                │
       │  6. Verify: SHA256(Kxy||M||Kxy) == MAC ?        │
       │                                                 │
       └─────────────────────────────────────────────────┘
```

## Technical Implementation

### Cryptographic Algorithms

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| Asymmetric Encryption | RSA with PKCS1 Padding | 1024-bit | Secure key distribution |
| Symmetric Encryption | AES in ECB mode | 128-bit | Fast message encryption |
| Hash Function | SHA-256 | 256-bit output | Message authentication |

### File Format Specifications

```
1. RSA Key Files (*.key)
   Format: Binary (ObjectOutputStream)
   Structure: [BigInteger n, BigInteger e/d]
   
2. Symmetric Key (symmetric.key)
   Format: UTF-8 Text
   Structure: 16-character string
   
3. Encrypted Message (message.aescipher)
   Format: Binary
   Structure: AES ciphertext blocks
   
4. Wrapped Key (kxy.rsacipher)
   Format: Binary
   Structure: Single RSA ciphertext block (128 bytes)
   
5. Keyed MAC (message.khmac)
   Format: Binary
   Structure: 32-byte SHA-256 hash
```

## Project Structure

```
CryptoGraphicProgram/
│
├── KeyGen/
│   └── KeyGen.java              # Cryptographic key generation
│       ├── Generates RSA keypairs (X and Y)
│       ├── Creates AES symmetric key
│       └── Outputs: XPublic.key, XPrivate.key,
│                    YPublic.key, YPrivate.key,
│                    symmetric.key
│
├── Sender/
│   └── Sender.java              # Message encryption & MAC creation
│       ├── Computes keyed hash MAC
│       ├── AES encrypts message
│       ├── RSA wraps symmetric key
│       └── Outputs: message.kmk, message.khmac,
│                    message.aescipher, kxy.rsacipher
│
└── Receiver/
    └── Receiver.java            # Message decryption & verification
        ├── RSA unwraps symmetric key
        ├── AES decrypts message
        ├── Verifies MAC authenticity
        └── Outputs: Decrypted message file
```

## Installation & Setup

### Prerequisites

- Java Development Kit (JDK) 8 or higher
- Command-line interface (Terminal/CMD)
- Basic understanding of cryptographic concepts

### Compilation

```bash
# Navigate to project root
cd CryptoGraphicProgram

# Compile KeyGen
cd KeyGen
javac KeyGen.java

# Compile Sender
cd ../Sender
javac Sender.java

# Compile Receiver
cd ../Receiver
javac Receiver.java
```

### Quick Setup Script

```bash
#!/bin/bash
# setup.sh - Compile all programs

echo "Compiling KeyGen..."
javac KeyGen/KeyGen.java

echo "Compiling Sender..."
javac Sender/Sender.java

echo "Compiling Receiver..."
javac Receiver/Receiver.java

echo "All programs compiled successfully!"
```

## Usage Guide

### Step 1: Generate Keys

```bash
cd KeyGen
java KeyGen.java
```

**Prompt**: Enter a 16-character AES key
**Example Input**: `MySecretKey12345`

**Output Files**:
- `XPublic.key`, `XPrivate.key` - Sender's RSA keypair
- `YPublic.key`, `YPrivate.key` - Receiver's RSA keypair
- `symmetric.key` - AES symmetric key

---

### Step 2: Encrypt Message (Sender)

```bash
cd Sender

# Copy required keys
cp ../KeyGen/YPublic.key .
cp ../KeyGen/symmetric.key .

# Run sender program
java Sender.Sender
```

**Prompts**:
1. `Input the name of the message file:` → Enter your file path
2. `Do you want to invert the 1st byte in SHA256(Kxy||M||Kxy)? (Y or N):` → Enter N for normal operation

**Output Files**:
- `message.kmk` - Kxy || Message || Kxy (for MAC computation)
- `message.khmac` - Keyed hash MAC (32 bytes)
- `message.aescipher` - AES encrypted message
- `kxy.rsacipher` - RSA encrypted symmetric key (128 bytes)

**Console Output Example**:
```
Keyed Hash MAC (SHA-256) = A1B2C3D4E5F6...
Wrote files: message.kmk, message.khmac, message.aescipher, kxy.rsacipher
```

---

### Step 3: Decrypt & Verify (Receiver)

```bash
cd Receiver

# Copy required files
cp ../KeyGen/YPrivate.key .
cp ../Sender/message.khmac .
cp ../Sender/message.aescipher .
cp ../Sender/kxy.rsacipher .

# Run receiver program
java Receiver.java
```

**Prompt**: `Input the name of the message file:` → Enter output filename

**Console Output Example**:
```
Recovered Kxy (hex): 4D795365637265744B657931323334...
Received MAC (sender) = A1B2C3D4E5F6...
Recomputed MAC       = A1B2C3D4E5F6...
Authentication PASSED
Decrypted message saved to: output.txt
```

---

### Example Workflow

```bash
# 1. Generate keys
cd KeyGen && java KeyGen.java
# Input: MySecretKey12345

# 2. Create test message
cd ../Sender
echo "Hello, secure world!" > test_message.txt

# 3. Encrypt
java Sender.java
# Input: test_message.txt
# Invert byte: N

# 4. Decrypt and verify
cd ../Receiver
java Receiver.java
# Output file: decrypted.txt

# 5. Verify files match
diff decrypted.txt ../Sender/test_message.txt
# No output = files are identical 
```

## Security Concepts

### 1. Hybrid Encryption

**Why not just RSA?**
- RSA is computationally expensive
- Limited message size (1024-bit key ≈ 117 bytes per block with padding)
- Slow for large files

**Why not just AES?**
- Requires secure key distribution
- Symmetric key must be shared securely

**Solution: Hybrid Approach**
- Use AES for fast message encryption (handles large files)
- Use RSA only for encrypting the small AES key (secure distribution)

### 2. Keyed Hash MAC

**Purpose**: Ensure message integrity and authenticity

**Construction**: `MAC = SHA256(Kxy || M || Kxy)`

**Why include the key?**
- Without key: Attacker can modify message and recompute hash
- With key: Only parties with Kxy can create valid MAC

**Why prefix AND suffix?**
- Prevents length extension attacks on the hash function
- Provides stronger security guarantees

### 3. Digital Envelope

**Concept**: Wrap the symmetric key with recipient's public key

**Benefits**:
- Only recipient (with private key) can unwrap the symmetric key
- Supports multiple recipients (encrypt Kxy with each recipient's public key)
- Separates key distribution from message encryption

### Security Properties Achieved

| Property | Mechanism | Attack Prevention |
|----------|-----------|-------------------|
| **Confidentiality** | AES encryption | Eavesdropping |
| **Authenticity** | Keyed MAC | Impersonation |
| **Integrity** | SHA-256 hash | Tampering |
| **Non-repudiation** | RSA signature* | Denial of sending |
| **Secure Key Exchange** | RSA encryption | Key interception |

*Note: This implementation uses MAC rather than digital signature

## Testing

### Test Case 1: Small Text File

```bash
# Create test file
echo "This is a test message." > test.txt

# Run through system
cd Sender && java Sender.java  # Input: test.txt, Invert: N
cd ../Receiver && java Receiver.java  # Output: out.txt

# Verify
diff out.txt ../Sender/test.txt  # Should be identical
```

**Expected Result**: Authentication PASSED, files match.

---

### Test Case 2: Large Binary File

```bash
# Create 10MB random binary file
dd if=/dev/urandom of=large.bin bs=1M count=10

# Encrypt and decrypt
cd Sender && java Sender.Sender  # Input: large.bin
cd ../Receiver && java Receiver.java  # Output: large_out.bin

# Verify with checksums
sha256sum large.bin large_out.bin
```

**Expected Result**: Identical SHA-256 hashes.

---

### Test Case 3: Authentication Failure

```bash
cd Sender && java Sender.java
# Input: test.txt
# Invert: Y  ← This corrupts the MAC

cd ../Receiver && java Receiver.java
# Output: out.txt
```

**Expected Result**: Authentication FAILED

**Console Output**:
```
Received MAC (sender) = FE23C1... (first byte inverted)
Recomputed MAC       = 01DC3E... (correct hash)
Authentication FAILED
```

---

### Automated Test Script

```bash
#!/bin/bash
# test.sh - Run comprehensive tests

echo "Running Cryptographic System Tests"

# Test 1: Text file
echo "Test 1: Small text file"
echo "Hello World" > test1.txt
cd Sender && java Sender.java <<< $'test1.txt\nN'
cd ../Receiver && java Receiver.java <<< 'out1.txt'
diff out1.txt ../Sender/test1.txt && echo " Test 1 PASSED"

# Test 2: Binary file
echo "Test 2: Binary file (1MB)"
dd if=/dev/urandom of=test2.bin bs=1K count=1024 2>/dev/null
cd Sender && java Sender.java <<< $'test2.bin\nN'
cd ../Receiver && java Receiver.java <<< 'out2.bin'
diff out2.bin ../Sender/test2.bin && echo "Test 2 PASSED"

# Test 3: MAC verification failure
echo "Test 3: MAC tampering detection"
cd Sender && java Sender.java <<< $'test1.txt\nY'
cd ../Receiver && java Receiver.java <<< 'out3.txt' | grep "FAILED" && echo "Test 3 PASSED"

echo "All tests completed!"
```

## Learning Outcomes

### Technical Skills Developed

- **Java Cryptography API**: `javax.crypto`, `java.security`
- **RSA Cryptography**: Key generation, encryption, decryption
- **AES Encryption**: Symmetric cipher operations
- **Hash Functions**: SHA-256 message digest
- **Binary I/O**: `ObjectInputStream/OutputStream`, `BufferedInputStream/OutputStream`
- **Stream Processing**: Handling large files efficiently
- **Security Protocols**: Digital envelope, MAC authentication

### Cryptographic Concepts Mastered

| Concept | Implementation | Real-world Application |
|---------|----------------|------------------------|
| Hybrid Encryption | RSA + AES | TLS/SSL, PGP |
| Message Authentication | Keyed MAC | HMAC in APIs |
| Key Distribution | Digital Envelope | Email encryption (S/MIME) |
| Integrity Verification | Hash comparison | Software downloads |
| Secure Communication | Complete system | Messaging apps |

##  Contributing

This project was developed as part of CS 3750: Computer and Network Security at MSU Denver. While primarily educational, suggestions for improvements are welcome!

### Areas for Enhancement

- [ ] Add support for multiple recipients
- [ ] Implement true digital signatures (RSA sign/verify)
- [ ] Add support for AES-GCM (authenticated encryption)
- [ ] Create GUI interface
- [ ] Add network socket communication
- [ ] Implement certificate-based authentication

##  License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

##  Author

**Brian Flores**
- GitHub: [@bfcortesss](https://github.com/bfcortesss)

<div align="center">

**If you found this project helpful, please consider giving it a star!**

Made with Java by Brian Flores

</div>
