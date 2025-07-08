// conn.go
package xrudp

import (
	"net"
	"time"
	"errors"
	"fmt"
	"io" // For io.EOF
	"crypto/tls" // For TLS integration
	"crypto/sha256" // For tls.ConnectionState.ExportKeyingMaterial size
	"log" // For logging
)

// Define MAX_PACKAGE locally to resolve "undefined" error.
// IMPORTANT: This constant is likely defined elsewhere in the xrudp package (e.g., rudp.go or conf.go).
// Defining it here might create a duplicate if those files are also compiled.
// The ideal fix would be to ensure proper visibility/import if it's in a separate file,
// or that the file defining it is part of the compilation unit.
const MAX_PACKAGE = 0x7fff // A common default max UDP payload size, or match your existing definition.


// NewConn creates a new connected XRUDP connection.
func NewConn(conn *net.UDPConn, xrudp *XRUDP) *XRUDPConn { // Changed return type to *XRUDPConn
	con := &XRUDPConn{conn: conn, xrudp: xrudp, // Changed struct name to XRUDPConn
		recvChan: make(chan []byte, 1<<16), recvErr: make(chan error, 2),
		sendChan: make(chan []byte, 1<<16), sendErr: make(chan error, 2),
		SendTick: make(chan struct{}, 2), // Use struct{} for tick signal
	}
	go con.run()
	return con
}

// NewUnConn creates a new unconnected XRUDP connection (for listener).
func NewUnConn(conn *net.UDPConn, remoteAddr *net.UDPAddr, xrudp *XRUDP, closef func(string)) *XRUDPConn { // Changed return type to *XRUDPConn
	con := &XRUDPConn{conn: conn, xrudp: xrudp, SendTick: make(chan struct{}, 2), // Changed struct name to XRUDPConn
		recvChan: make(chan []byte, 1<<16), recvErr: make(chan error, 2),
		sendChan: make(chan []byte, 1<<16), sendErr: make(chan error, 2),
		closef: closef, remoteAddr: remoteAddr, in: make(chan []byte, 1<<16),
	}
	go con.run()
	return con
}

// XRUDPConn represents an XRUDP connection. It also implements net.Conn.
type XRUDPConn struct { // Changed struct name from RudpConn to XRUDPConn
	conn *net.UDPConn // Underlying UDP connection

	xrudp *XRUDP // Core XRUDP protocol instance.
	              // IMPORTANT: For TLS integration, the XRUDP struct in xrudp.go
	              // MUST have a field 'crypto *CryptoSuite' and a method 'Connected() bool'.
	              // If these are missing, compilation will fail on xrudp.go after this change.

	recvChan chan []byte // Channel for application to read received data (from default stream)
	recvErr  chan error  // Channel for receive errors

	sendChan chan []byte // Channel for application to write data (to default stream)
	sendErr  chan error  // Channel for send errors

	SendTick chan struct{} // Internal tick for XRUDP.Update()

	// Unconnected mode (for listener-managed connections)
	remoteAddr *net.UDPAddr // Remote address for unconnected mode (set by listener)
	closef     func(addr string) // Callback for listener to close this connection
	in         chan []byte // Channel for listener to feed incoming UDP packets

	// TLS Integration: This field holds the TLS connection wrapper.
	tlsConn *tls.Conn
}

// Implement net.Conn interface methods

// Read reads data from the XRUDP connection's default stream.
// This method is called by the tls.Conn wrapper (if present) or directly by the application.
// It reads raw (possibly encrypted by TLS) bytes from the underlying XRUDP stream.
func (rc *XRUDPConn) Read(b []byte) (n int, err error) { // Changed receiver type to *XRUDPConn
	select {
	case data := <-rc.recvChan: // This channel is fed by rc.xrudpRecvLoop
		n = copy(b, data)
		if n < len(data) {
			// This is a simplification. Real net.Conn Read needs to handle partial reads correctly
			// by buffering the remaining data. For this example, we log a warning and discard.
			log.Printf("[XRUDP_WARN] XRUDPConn.Read: Buffer too small (%d bytes), discarding %d bytes from XRUDP stream.", len(b), len(data)-n)
		}
		return n, nil
	case err := <-rc.recvErr:
		return 0, err
	case <-rc.xrudp.close: // Check if XRUDP core is closing
		return 0, io.EOF // Or appropriate error
	}
}

// Write writes data to the XRUDP connection's default stream.
// This method is called by the tls.Conn wrapper (if present) or directly by the application.
// It writes raw (possibly encrypted by TLS) bytes to the underlying XRUDP stream.
func (rc *XRUDPConn) Write(b []byte) (n int, err error) { // Changed receiver type to *XRUDPConn
	select {
	case rc.sendChan <- b: // This channel is read by rc.sendLoop
		return len(b), nil
	case err := <-rc.sendErr:
		return 0, err
	case <-rc.xrudp.close: // Check if XRUDP core is closing
		return 0, io.EOF
	}
}

// LocalAddr returns the local network address.
func (rc *XRUDPConn) LocalAddr() net.Addr { // Changed receiver type to *XRUDPConn
	return rc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (rc *XRUDPConn) RemoteAddr() net.Addr { // Changed receiver type to *XRUDPConn
	// In connected mode, conn.RemoteAddr() is valid.
	// In unconnected mode, rc.remoteAddr is set by the listener.
	if rc.remoteAddr != nil {
		return rc.remoteAddr
	}
	return rc.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// For UDP, deadlines are tricky. For simplicity, this is a no-op.
func (rc *XRUDPConn) SetDeadline(t time.Time) error { // Changed receiver type to *XRUDPConn
	// return rc.conn.SetDeadline(t) // This would apply to the raw UDP socket
	return nil // No-op for now, as XRUDP has its own timeouts
}

// SetReadDeadline sets the read deadline.
func (rc *XRUDPConn) SetReadDeadline(t time.Time) error { // Changed receiver type to *XRUDPConn
	// return rc.conn.SetReadDeadline(t)
	return nil // No-op
}

// SetWriteDeadline sets the write deadline.
func (rc *XRUDPConn) SetWriteDeadline(t time.Time) error { // Changed receiver type to *XRUDPConn
	// return rc.conn.SetWriteDeadline(t)
	return nil // No-op
}

// Close closes the XRUDP connection.
func (rc *XRUDPConn) Close() error { // Changed receiver type to *XRUDPConn
	var err error
	// If TLS connection exists, close it first.
	if rc.tlsConn != nil {
		tlsErr := rc.tlsConn.Close()
		if tlsErr != nil {
			log.Printf("[XRUDP_ERROR] Error closing TLS connection: %v", tlsErr)
			err = errors.Join(err, tlsErr)
		}
	}

	// Signal XRUDP core to close and send RST
	xrudpErr := rc.xrudp.Close()
	if xrudpErr != nil {
		log.Printf("[XRUDP_ERROR] Error closing XRUDP core: %v", xrudpErr)
		err = errors.Join(err, xrudpErr)
	}

	// Notify listener to clean up if in unconnected mode
	if rc.remoteAddr != nil && rc.closef != nil {
		rc.closef(rc.remoteAddr.String())
	}

	// Close channels to stop goroutines
	close(rc.SendTick)
	close(rc.recvChan)
	close(rc.sendChan)
	close(rc.recvErr)
	close(rc.sendErr)
	if rc.in != nil { // Only close if it's an unconnected conn
		close(rc.in)
	}
	dbg("XRUDPConn closed for remote %s", rc.RemoteAddr())
	return err
}

// ClientTLSHandshake performs the client-side TLS 1.3 handshake over XRUDP.
// It initializes the CryptoSuite with the derived application traffic secret.
func (rc *XRUDPConn) ClientTLSHandshake(config *tls.Config) error { // Changed receiver type to *XRUDPConn
	if rc.tlsConn != nil {
		return errors.New("TLS handshake already performed")
	}

	// Create a tls.Client that wraps this XRUDPConn (which implements net.Conn)
	rc.tlsConn = tls.Client(rc, config)

	// Perform the TLS handshake
	err := rc.tlsConn.Handshake()
	if err != nil {
		rc.tlsConn = nil // Clear tlsConn on handshake failure
		return fmt.Errorf("TLS client handshake failed: %w", err)
	}

	// Get the TLS ConnectionState to export keying material
	tlsState := rc.tlsConn.ConnectionState()
	if !tlsState.HandshakeComplete {
		rc.tlsConn = nil
		return errors.New("TLS handshake not complete after Handshake() call")
	}

	// Export the application traffic secret (TLS 1.3 specific)
	// The label "EXPORTER-XRUDP-TRAFFIC" is arbitrary but should be unique.
	// The context is nil for application traffic secrets.
	// The length should match the hash size used in HKDF (SHA256.Size = 32 bytes).
	tlsSecret, err := tlsState.ExportKeyingMaterial("EXPORTER-XRUDP-TRAFFIC", nil, sha256.Size)
	if err != nil {
		rc.tlsConn = nil
		return fmt.Errorf("failed to export TLS keying material: %w", err)
	}

	// Initialize the XRUDP CryptoSuite with the derived TLS secret
	// This re-initializes the CryptoSuite with the real TLS secrets.
	// This assumes rc.xrudp (which is *XRUDP) has a field named 'crypto' of type *CryptoSuite.
	err = rc.xrudp.crypto.InitializeCryptoSuite(tlsSecret, true) // true for client
	if err != nil {
		rc.tlsConn = nil
		return fmt.Errorf("failed to initialize XRUDP CryptoSuite with TLS secret: %w", err)
	}

	log.Printf("[xrudp] Client TLS handshake successful. XRUDP CryptoSuite initialized.")
	return nil
}

// ServerTLSHandshake performs the server-side TLS 1.3 handshake over XRUDP.
// It initializes the CryptoSuite with the derived application traffic secret.
func (rc *XRUDPConn) ServerTLSHandshake(config *tls.Config) error { // Changed receiver type to *XRUDPConn
	if rc.tlsConn != nil {
		return errors.New("TLS handshake already performed")
	}

	// Create a tls.Server that wraps this XRUDPConn (which implements net.Conn)
	rc.tlsConn = tls.Server(rc, config)

	// Perform the TLS handshake
	err := rc.tlsConn.Handshake()
	if err != nil {
		rc.tlsConn = nil // Clear tlsConn on handshake failure
		return fmt.Errorf("TLS server handshake failed: %w", err)
	}

	// Get the TLS ConnectionState to export keying material
	tlsState := rc.tlsConn.ConnectionState()
	if !tlsState.HandshakeComplete {
		rc.tlsConn = nil
		return errors.New("TLS handshake not complete after Handshake() call")
	}

	// Export the application traffic secret (TLS 1.3 specific)
	tlsSecret, err := tlsState.ExportKeyingMaterial("EXPORTER-XRUDP-TRAFFIC", nil, sha256.Size)
	if err != nil {
		rc.tlsConn = nil
		return fmt.Errorf("failed to export TLS keying material: %w", err)
	}

	// Initialize the XRUDP CryptoSuite with the derived TLS secret
	// This re-initializes the CryptoSuite with the real TLS secrets.
	// This assumes rc.xrudp (which is *XRUDP) has a field named 'crypto' of type *CryptoSuite.
	err = rc.xrudp.crypto.InitializeCryptoSuite(tlsSecret, false) // false for server
	if err != nil {
		rc.tlsConn = nil
		return fmt.Errorf("failed to initialize XRUDP CryptoSuite with TLS secret: %w", err)
	}

	log.Printf("[xrudp] Server TLS handshake successful. XRUDP CryptoSuite initialized.")
	return nil
}

// xrudpRecvLoop continuously tries to receive data from the XRUDP core and
// pushes it to the application-facing recvChan.
func (rc *XRUDPConn) xrudpRecvLoop(data []byte) error { // Changed receiver type to *XRUDPConn
	for {
		// Attempt to read from default stream (Stream ID 1)
		// This is the raw data from XRUDP, potentially encrypted by TLS.
		n, err := rc.xrudp.Recv(1, data)
		if err != nil {
			rc.recvErr <- err
			return err
		}
		if n == 0 {
			// No data currently available, wait for next tick or input
			break
		}
		
		// Copy data and send to application channel
		bts := make([]byte, n)
		copy(bts, data[:n])
		select {
		case rc.recvChan <- bts:
			// Data sent to application
		case <-rc.xrudp.close: // Check if XRUDP core is closing
			return rc.xrudp.error.Error()
		default:
			dbg("recvChan full for remote %s, dropping data from XRUDP core.", rc.RemoteAddr())
			// In a real system, this would indicate a problem with application consumption
			// or buffer management.
		}
	}
	return nil
}

// conectedRecvLoop handles incoming UDP packets for a connected socket.
func (rc *XRUDPConn) conectedRecvLoop() { // Changed receiver type to *XRUDPConn
	data := make([]byte, MAX_PACKAGE) // Use MAX_PACKAGE for buffer (assuming it's defined elsewhere, e.g., in xrudp.go or conf.go)
	for {
		n, err := rc.conn.Read(data)
		if err != nil {
			rc.recvErr <- err
			return
		}
		// Pass remote address for connection migration logic
		err = rc.xrudp.Input(data[:n], rc.RemoteAddr().(*net.UDPAddr))
		if err != nil {
			dbg("Error processing input for %s: %v", rc.RemoteAddr(), err)
			// Depending on error, might close connection. For now, just log.
		}
		// Attempt to pull data from XRUDP core
		if rc.xrudpRecvLoop(data) != nil {
			return
		}
	}
}

// unconectedRecvLoop handles incoming UDP packets for an unconnected socket (listener mode).
func (rc *XRUDPConn) unconectedRecvLoop() { // Changed receiver type to *XRUDPConn
	data := make([]byte, MAX_PACKAGE) // Use MAX_PACKAGE for buffer
	for {
		select {
		case bts, ok := <-rc.in: // Read from channel fed by listener
			if !ok { // Channel closed
				return
			}
			// Pass the fixed remote address (set by listener initially)
			err := rc.xrudp.Input(bts, rc.remoteAddr)
			if err != nil {
				dbg("Error processing input for %s: %v", rc.remoteAddr, err)
			}
			// Attempt to pull data from XRUDP core
			if rc.xrudpRecvLoop(data) != nil {
				return
			}
		case <-rc.xrudp.close: // Check if XRUDP core is closing
			return
		}
	}
}

// sendLoop continuously updates the XRUDP core and sends out generated packets.
func (rc *XRUDPConn) sendLoop() { // Changed receiver type to *XRUDPConn
	ticker := time.NewTicker(rc.xrudp.conf.SendTick)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Trigger XRUDP core update
			p := rc.xrudp.Update()
			var numPacketsSent int
			var totalBytesSent int
			for p != nil {
				n, err := int(0), error(nil)
				// Determine destination address: use XRUDP's currentRemoteAddr for sending
				// This allows XRUDP core to control which path to send on during migration.
				destAddr := rc.xrudp.currentRemoteAddr
				if destAddr == nil { // Fallback if currentRemoteAddr not set (e.g., during initial client SYN)
					destAddr = rc.RemoteAddr().(*net.UDPAddr)
				}

				if rc.xrudp.Connected() { // Use rc.xrudp.Connected()
					n, err = rc.conn.Write(p.Bts)
				} else { // For unconnected UDP socket (listener-managed)
					n, err = rc.conn.WriteToUDP(p.Bts, destAddr)
				}

				if err != nil {
					rc.sendErr <- err
					dbg("Error sending UDP packet to %s: %v", destAddr, err)
					// Consider if this error should close the connection
					return
				}
				totalBytesSent += n
				numPacketsSent++
				p = p.Next
			}
			if numPacketsSent > 0 {
				dbg("Sent %d packets, total %s. Local %v, Remote %v",
					numPacketsSent, bitShow(totalBytesSent), rc.LocalAddr(), rc.RemoteAddr())
			}
		case <-rc.xrudp.close: // Check if XRUDP core is closing
			return // Exit loop
		}
	}
}

// run starts the main loops for the XRUDP connection.
func (rc *XRUDPConn) run() { // Changed receiver type to *XRUDPConn
	// Start receive loop
	go func() {
		if rc.xrudp.Connected() { // Use rc.xrudp.Connected()
			rc.conectedRecvLoop()
		} else {
			rc.unconectedRecvLoop()
		}
	}()

	// Start send loop (driven by ticker)
	rc.sendLoop()
}
