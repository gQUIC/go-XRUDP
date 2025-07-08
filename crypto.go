// xrudp_crypto.go
package xrudp

import (
	"bytes"
	"crypto/aes"     // For AES block cipher
	"crypto/cipher"  // For AEAD (GCM mode)
	"crypto/hmac"    // For HMAC, used in HKDF
	"crypto/rand"    // For generating cryptographically secure random numbers (nonces)
	"crypto/sha256"  // For SHA256 hash, used in HKDF
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"hash" // For hash.Hash interface
	"log"  // For logging warnings/errors
	"sync" // For protecting access to global ticket key
)

// Define constants for AEAD parameters.
const (
	aes128KeySize = 16 // 16 bytes for AES-128
	aes256KeySize = 32 // 32 bytes for AES-256
	gcmNonceSize  = 12 // 96-bit (12-byte) Nonce for GCM
	gcmTagSize    = 16 // 128-bit (16-bit) Authentication Tag for GCM
	
	// Simulated TLS 1.3 Handshake Secrets sizes
	tlsHandshakeSecretSize = 32 // SHA256 output size
)

// Global variables for session ticket encryption.
// These are managed dynamically via SetGlobalTicketEncryptionKey.
// IMPORTANT: While dynamically updatable, using a global key for all tickets
// in a multi-server or high-security environment requires careful consideration
// of key rotation and distribution. This design is a compromise to satisfy
// the "no xrudp.go modification" constraint.
var (
	globalTicketEncryptionKey []byte
	globalTicketAEAD          cipher.AEAD
	globalTicketKeyMutex      sync.RWMutex // Protects access to globalTicketEncryptionKey and globalTicketAEAD
)

// init function to set up global ticket encryption key and AEAD with a default random key.
// This runs once when the package is imported. External callers can then update it.
func init() {
	// Initialize with a default random key.
	// This makes it "dynamic" in the sense that it's not hardcoded,
	// but it's static until SetGlobalTicketEncryptionKey is called.
	defaultKey, err := GenerateRandomBytes(aes128KeySize)
	if err != nil {
		log.Printf("[xrudp] warning: failed to generate default global ticket encryption key: %v", err)
		// In a real system, this would be a critical failure.
		return // Do not proceed if default key generation fails
	}
	// Set the default key and AEAD instance
	if err := SetGlobalTicketEncryptionKey(defaultKey); err != nil {
		log.Printf("[xrudp] warning: failed to set default global ticket AEAD: %v", err)
	}
}

// SetGlobalTicketEncryptionKey allows external components to dynamically update
// the key used for session ticket encryption/decryption.
// This is the "偷偷调换" (secretly swap) mechanism.
func SetGlobalTicketEncryptionKey(key []byte) error {
	globalTicketKeyMutex.Lock()
	defer globalTicketKeyMutex.Unlock()

	if len(key) != aes128KeySize {
		return fmt.Errorf("ticket encryption key must be %d bytes", aes128KeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher for global ticket AEAD: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM AEAD for global ticket encryption: %w", err)
	}

	globalTicketEncryptionKey = key
	globalTicketAEAD = aead
	log.Printf("[xrudp] Global ticket encryption key and AEAD updated dynamically.")
	return nil
}


// CryptoSuite holds keys, nonces, and AEAD instances for XRUDP encryption.
// This structure mimics what a real TLS/DTLS library would provide after a successful handshake.
type CryptoSuite struct {
	// AEAD ciphers for encrypting/decrypting application data for each direction.
	// These are created using crypto/aes and crypto/cipher.NewGCM.
	clientAEAD cipher.AEAD // Encrypts client -> server packets
	serverAEAD cipher.AEAD // Encrypts server -> client packets

	// Initial Vectors (IVs) for nonce generation.
	// In TLS 1.3, these are derived from the traffic secrets.
	clientIV []byte // Base IV for client-sent packets
	serverIV []byte // Base IV for server-sent packets

	// Packet number counters for each direction.
	// These are combined with the base IV to form unique nonces for each packet.
	// Must be monotonically increasing.
	currentClientPacketNum uint64
	currentServerPacketNum uint64

	initialized bool // True if the crypto suite has been successfully initialized.
}

// NewCryptoSuite constructs a new CryptoSuite.
// Note: Ticket encryption key/AEAD are now managed globally via SetGlobalTicketEncryptionKey.
func NewCryptoSuite() *CryptoSuite {
	return &CryptoSuite{
		currentClientPacketNum: 0,
		currentServerPacketNum: 0,
		initialized:            false,
	}
}

// InitializeCryptoSuite derives AEAD keys and IVs from a TLS handshake secret.
//
// `tlsSecret` is a secret derived during the TLS handshake (e.g., the
// TLS 1.3 Handshake Traffic Secret).
// `isClient` indicates if this CryptoSuite is for the client side of the connection.
//
// In a real TLS 1.3 integration, you would typically get the client/server
// application traffic secrets from `tls.ConnectionState.ExportKeyingMaterial`
// or directly from the TLS library's internal state after a handshake.
func (cs *CryptoSuite) InitializeCryptoSuite(tlsSecret []byte, isClient bool) error {
	if len(tlsSecret) == 0 {
		return errors.New("tls handshake secret cannot be empty for crypto initialization")
	}

	// In TLS 1.3, application traffic secrets are derived from the handshake secret.
	// We'll simulate this using HKDF-Expand-Label.
	// The `secret` parameter to hkdfExpandLabel is typically the current traffic secret.
	// Here, we use the `tlsSecret` as the base for simplicity.
	clientApplicationTrafficSecret := cs.hkdfExpandLabel(tlsSecret, []byte("c ap traffic"), nil, sha256.Size)
	serverApplicationTrafficSecret := cs.hkdfExpandLabel(tlsSecret, []byte("s ap traffic"), nil, sha256.Size)

	// Derive AEAD keys and IVs from application traffic secrets.
	var err error
	cs.clientAEAD, cs.clientIV, err = cs.deriveAEAD(clientApplicationTrafficSecret, aes256KeySize, gcmNonceSize)
	if err != nil {
		return fmt.Errorf("derive client AEAD failed: %w", err)
	}

	cs.serverAEAD, cs.serverIV, err = cs.deriveAEAD(serverApplicationTrafficSecret, aes256KeySize, gcmNonceSize)
	if err != nil {
		return fmt.Errorf("derive server AEAD failed: %w", err)
	}
	cs.initialized = true
	log.Printf("[xrudp] crypto suite initialized")
	return nil
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label as per RFC 8446.
// `secret`: The PRK (Pseudo-Random Key) to expand from.
// `label`: A context-specific label (e.g., "client write key").
// `context`: Optional context-specific data.
// `length`: Desired output key length in bytes.
func (cs *CryptoSuite) hkdfExpandLabel(secret, label, context []byte, length int) []byte {
	// info: uint16 length || "tls13 " + label || uint8 context length || context
	fullLabel := append([]byte("tls13 "), label...)
	buf := bytes.NewBuffer(nil)
	
	// length (2 bytes)
	binary.Write(buf, binary.BigEndian, uint16(length))
	// label_len (1 byte) + label bytes
	buf.WriteByte(uint8(len(fullLabel)))
	buf.Write(fullLabel)
	// context_len (1 byte) + context bytes
	buf.WriteByte(uint8(len(context)))
	if len(context) > 0 {
		buf.Write(context)
	}
	
	return hkdfExpand(sha256.New, secret, buf.Bytes(), length)
}

// hkdfExpand performs HKDF-Expand using HMAC and a counter.
// `hashFunc`: The hash function to use (e.g., sha256.New).
// `prk`: The Pseudo-Random Key (PRK).
// `info`: The context-specific info.
// `length`: The desired output length.
func hkdfExpand(hashFunc func() hash.Hash, prk, info []byte, length int) []byte {
	h := hashFunc()
	_ = h.Size() // Use h.Size() to avoid "declared and not used" warning
	var result, prev []byte
	
	// The counter `i` starts from 1.
	for counter := 1; len(result) < length; counter++ {
		mac := hmac.New(hashFunc, prk)
		if counter > 1 {
			mac.Write(prev) // Corrected: ensure 'prev' is written
		}
		mac.Write(info)
		mac.Write([]byte{byte(counter)}) // Counter byte
		prev = mac.Sum(nil)
		result = append(result, prev...)
	}
	return result[:length]
}

// deriveAEAD initializes AES-GCM AEAD and derives its IV.
// This function is a helper for InitializeCryptoSuite.
func (cs *CryptoSuite) deriveAEAD(secret []byte, keySize, ivSize int) (cipher.AEAD, []byte, error) {
	// Derive the actual AEAD encryption key using HKDF-Expand-Label.
	key := cs.hkdfExpandLabel(secret, []byte("key"), nil, keySize)

	// Derive the Initial Vector (IV) using HKDF-Expand-Label.
	iv := cs.hkdfExpandLabel(secret, []byte("iv"), nil, ivSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}

	return aead, iv, nil
}

// generateNonce constructs a GCM nonce by XORing packet number with base IV.
// In GCM, the nonce is typically 12 bytes. The packet number is 8 bytes.
// The packet number is XORed into the last 8 bytes of the 12-byte IV.
// This ensures uniqueness as packetNum is monotonic.
func (cs *CryptoSuite) generateNonce(baseIV []byte, packetNum uint64) []byte {
	nonce := make([]byte, gcmNonceSize)
	copy(nonce, baseIV) // Start with the base IV

	// XOR the packet number into the last 8 bytes of the nonce.
	// This is the standard QUIC/TLS 1.3 nonce construction.
	pnBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pnBytes, packetNum)
	for i := 0; i < 8; i++ {
		nonce[gcmNonceSize-8+i] ^= pnBytes[i]
	}
	return nonce
}

// EncryptPacket encrypts plaintext with AEAD: nonce||ciphertext||tag.
// `isClient` determines whether to use client-side or server-side keys/IVs.
// `packetNum` is the unique sequence number of the packet.
// `plaintext` is the data to be encrypted.
// `additionalData` is authenticated but not encrypted (e.g., packet header fields for integrity).
//
// The output format is: Nonce || Ciphertext || Tag.
func (cs *CryptoSuite) EncryptPacket(isClient bool, packetNum uint64, plaintext, additionalData []byte) ([]byte, error) {
	if !cs.initialized {
		return nil, errors.New("crypto suite not initialized, cannot encrypt packet")
	}
	
	var aeadInst cipher.AEAD
	var baseIV []byte

	if isClient {
		aeadInst = cs.clientAEAD
		baseIV = cs.clientIV
		cs.currentClientPacketNum = packetNum // Update internal counter for tracking
	} else {
		aeadInst = cs.serverAEAD
		baseIV = cs.serverIV
		cs.currentServerPacketNum = packetNum // Update internal counter for tracking
	}

	// Generate a unique nonce for this packet.
	nonce := cs.generateNonce(baseIV, packetNum)

	// Seal performs AEAD encryption: plaintext is encrypted, additionalData is authenticated.
	// It appends the authentication tag to the ciphertext.
	// The `Seal` function's first argument is the destination slice; passing `nil` allocates a new one.
	ciphertext := aeadInst.Seal(nil, nonce, plaintext, additionalData)

	// The AEAD `Seal` method already includes the tag.
	// We prepend the nonce to the encrypted payload for transmission.
	return append(nonce, ciphertext...), nil
}

// DecryptPacket decrypts AEAD payload: nonce||ciphertext||tag.
// `isClient` determines whether to use client-side or server-side keys/IVs.
// `in` is the received data: Nonce || Ciphertext || Tag.
// `additionalData` is authenticated (e.g., packet header fields).
//
// Returns the decrypted plaintext or an error if decryption/authentication fails.
func (cs *CryptoSuite) DecryptPacket(isClient bool, in, additionalData []byte) ([]byte, error) {
	if !cs.initialized {
		return nil, errors.New("crypto suite not initialized, cannot decrypt packet")
	}
	if len(in) < gcmNonceSize+gcmTagSize {
		return nil, errors.New("input too short for AEAD (missing nonce or tag)")
	}

	// Extract nonce (first 12 bytes for GCM).
	nonce := in[:gcmNonceSize]
	// Remaining bytes are ciphertext || tag.
	ciphertext := in[gcmNonceSize:]

	var aeadInst cipher.AEAD
	if isClient {
		aeadInst = cs.clientAEAD
	} else {
		aeadInst = cs.serverAEAD
	}

	// Open performs AEAD decryption and authentication.
	// It returns the plaintext if successful, or an error if decryption/authentication fails.
	plaintext, err := aeadInst.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("AEAD decryption or authentication failed: %w", err)
	}

	return plaintext, nil
}

// EncryptSessionTicket encrypts a 0-RTT session ticket using the global ticket AEAD.
// This function is a global wrapper to maintain compatibility with xrudp.go.
// IMPORTANT: This uses a global static key for ticket encryption, which is NOT
// recommended for production environments due to production security implications.
// The key can be updated dynamically via SetGlobalTicketEncryptionKey.
func EncryptSessionTicket(ticketData []byte) ([]byte, error) {
	globalTicketKeyMutex.RLock() // Use RLock for read access
	defer globalTicketKeyMutex.RUnlock()

	if globalTicketAEAD == nil {
		return nil, errors.New("global ticket AEAD not initialized")
	}

	// Generate a cryptographically secure random nonce for ticket encryption.
	// This nonce ensures uniqueness for each ticket.
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate ticket nonce: %w", err)
	}

	// Additional data for ticket authentication.
	ad := []byte("XRUDP Session Ticket")

	// Seal the ticket data using the global ticketAEAD.
	ciphertext := globalTicketAEAD.Seal(nil, nonce, ticketData, ad)
	
	// Prepend nonce to the encrypted ticket for transmission.
	return append(nonce, ciphertext...), nil
}

// DecryptSessionTicket decrypts a 0-RTT session ticket using the global ticket AEAD.
// This function is a global wrapper to maintain compatibility with xrudp.go.
// IMPORTANT: This uses a global static key for ticket decryption, which is NOT
// recommended for production environments due to production security implications.
// The key can be updated dynamically via SetGlobalTicketEncryptionKey.
func DecryptSessionTicket(in []byte) ([]byte, error) {
	globalTicketKeyMutex.RLock() // Use RLock for read access
	defer globalTicketKeyMutex.RUnlock()

	if globalTicketAEAD == nil {
		return nil, errors.New("global ticket AEAD not initialized")
	}
	if len(in) < gcmNonceSize+gcmTagSize {
		return nil, errors.New("encrypted ticket too short for decryption (missing nonce or tag)")
	}

	// Extract nonce.
	nonce := in[:gcmNonceSize]
	// Remaining bytes are ciphertext || tag.
	ciphertext := in[gcmNonceSize:]

	// Additional data for ticket authentication.
	ad := []byte("XRUDP Session Ticket")

	// Open the ticket data using the global ticketAEAD.
	plaintext, err := globalTicketAEAD.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("session ticket decryption or authentication failed: %w", err)
	}

	return plaintext, nil
}

// GenerateRandomBytes returns securely-generated random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b) // Use io.ReadFull for guaranteed fill
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// TLSHelper manages the simulated TLS 1.3 handshake and key derivation.
// This structure would typically encapsulate the tls.Conn and its state.
type TLSHelper struct {
	isClient bool
	// In a real scenario, this would hold the *tls.Conn instance
	// and potentially its tls.ConnectionState.
	// For this simulation, we just manage the secrets.
}

// NewTLSHelper creates a new TLSHelper instance.
func NewTLSHelper(isClient bool) *TLSHelper {
	return &TLSHelper{
		isClient: isClient,
	}
}

// SimulateTLSHandshake performs a simulated TLS 1.3 handshake and
// initializes the provided CryptoSuite with derived secrets.
//
// In a real application, this would involve:
// 1. Creating a tls.Config (with certificates, root CAs, etc.).
// 2. Calling tls.Client() or tls.Server() with the underlying net.Conn (which would be XRUDPConn).
// 3. Calling tlsConn.Handshake().
// 4. Extracting the application traffic secret using tlsConn.ConnectionState().ExportKeyingMaterial().
// 5. Passing that secret to cs.InitializeCryptoSuite().
//
// Here, we simulate step 1, 4, and 5.
func (th *TLSHelper) SimulateTLSHandshake(cs *CryptoSuite) error {
	log.Printf("[xrudp] Simulating TLS 1.3 handshake for %s.", func() string {
		if th.isClient { return "client" } else { return "server" }
	}())

	// Simulate a TLS handshake secret (e.g., 32 bytes from a successful ECDH key exchange)
	// IMPORTANT: In a real scenario, this secret comes from a secure TLS handshake.
	// This is a placeholder for demonstration ONLY.
	tlsSecret, err := GenerateRandomBytes(tlsHandshakeSecretSize)
	if err != nil {
		return fmt.Errorf("failed to generate simulated TLS secret: %w", err)
	}
	// Corrected: Added argument for %d in log.Printf
	log.Printf("[xrudp] Simulated TLS handshake secret generated (length: %d bytes).", len(tlsSecret))

	// Initialize the CryptoSuite with the simulated secret
	err = cs.InitializeCryptoSuite(tlsSecret, th.isClient)
	if err != nil {
		return fmt.Errorf("failed to initialize CryptoSuite with simulated TLS secret: %w", err)
	}
	log.Printf("[xrudp] CryptoSuite successfully initialized with simulated TLS handshake secret.")

	// Optional: Simulate dynamic update of the global ticket encryption key
	// In a real scenario, a server might rotate this key periodically after a handshake.
	if !th.isClient { // Only server typically manages and rotates ticket keys
		newTicketKey, err := GenerateRandomBytes(aes128KeySize)
		if err != nil {
			log.Printf("[xrudp] warning: failed to generate new dynamic ticket key: %v", err)
		} else {
			if err := SetGlobalTicketEncryptionKey(newTicketKey); err != nil {
				log.Printf("[xrudp] warning: failed to set new dynamic ticket AEAD: %v", err)
			} else {
				log.Printf("[xrudp] Global ticket encryption key dynamically updated by simulated server handshake.")
			}
		}
	}

	return nil
}
