// xrudp_util.go
package xrudp

import (
	"fmt"
	"log"
	"time"
	"crypto/rand" // For generating cryptographically secure random numbers
	"encoding/binary"
)

// dbg prints debug messages if debug is enabled.
func dbg(format string, v ...interface{}) {
	// Use the global 'debug' variable from xrudp_conf.go
	if debug {
		log.Printf("[XRUDP_DEBUG] "+format, v...)
	}
}

// checkErr logs an error if it's not nil.
func checkErr(err error) {
	if err != nil {
		log.Printf("[XRUDP_ERROR] %v", err)
	}
}

// bitShow converts a byte count to a human-readable string (B, KB, MB).
func bitShow(n int) string {
	var ext string = "B"
	if n >= 1024 {
		n /= 1024
		ext = "KB"
	}
	if n >= 1024 {
		n /= 1024
		ext = "MB"
	}
	return fmt.Sprintf("%v %v", n, ext)
}

// calculateChecksum calculates the 16-bit one's complement checksum.
// This is a basic checksum for integrity, NOT for cryptographic security.
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8 // Pad with zero if odd length
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

// generateConnectionID generates a cryptographically secure 64-bit Connection ID.
func generateConnectionID() uint64 {
	var id uint64
	err := binary.Read(rand.Reader, binary.BigEndian, &id)
	if err != nil {
		// Fallback to time-based if crypto/rand fails, but log a warning.
		log.Printf("[XRUDP_WARN] Failed to generate cryptographically secure CID: %v. Using time-based fallback.", err)
		return uint64(time.Now().UnixNano())
	}
	return id
}

// generateStreamID generates a new stream ID based on the initiator.
// Client-initiated streams are odd, server-initiated are even.
// This function is a placeholder for a more robust stream ID allocation strategy.
func generateStreamID(isClient bool, currentMaxID uint32) uint32 {
	if isClient {
		// Ensure it's odd
		if currentMaxID%2 == 0 {
			return currentMaxID + 1
		}
		return currentMaxID + 2 // Next odd
	} else {
		// Ensure it's even
		if currentMaxID%2 != 0 {
			return currentMaxID + 1
		}
		return currentMaxID + 2 // Next even
	}
}

// encryptSessionTicket is a wrapper for the global EncryptSessionTicket function in xrudp_crypto.
// This allows xrudp.go to call it without needing a CryptoSuite instance.
func encryptSessionTicket(data []byte) ([]byte, error) {
	// Call the global EncryptSessionTicket function from the xrudp_crypto package.
	return EncryptSessionTicket(data)
}

// decryptSessionTicket is a wrapper for the global DecryptSessionTicket function in xrudp_crypto.
// This allows xrudp.go to call it without needing a CryptoSuite instance.
func decryptSessionTicket(data []byte) ([]byte, error) {
	// Call the global DecryptSessionTicket function from the xrudp_crypto package.
	return DecryptSessionTicket(data)
}
