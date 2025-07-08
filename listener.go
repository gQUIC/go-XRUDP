// xrudp_listener.go
package xrudp

import (
	"net"
	"sync"
)

// NewListener creates a new XRUDP listener.
func NewListener(conn *net.UDPConn) *XRUDPListener {
	listen := &XRUDPListener{conn: conn,
		newXRUDPConn: make(chan *XRUDPConn, 1024),
		newXRUDPErr:  make(chan error, 12), // Corrected: Removed U+00A0
		xrudpConnMap: make(map[string]*XRUDPConn), // Map remoteAddr.String() to XRUDPConn
		connIDMap:    make(map[uint64]*XRUDPConn), // Map primary ConnectionID to XRUDPConn // Corrected: Removed U+00A0
	}
	go listen.run()
	return listen
}

// XRUDPListener listens for incoming XRUDP connections.
type XRUDPListener struct {
	conn *net.UDPConn // Underlying UDP connection
	lock sync.RWMutex // Protects maps

	newXRUDPConn chan *XRUDPConn // Channel for new accepted connections
	newXRUDPErr  chan error      // Channel for listener errors // Corrected: Removed U+00A0
	
	// Maps to manage active connections.
	// xrudpConnMap: Primarily for initial connection lookup by remote address.
	// connIDMap: For established connections and connection migration, maps primary CID to connection.
	xrudpConnMap map[string]*XRUDPConn // Key: remoteAddr.String()
	connIDMap    map[uint64]*XRUDPConn // Key: Connection ID // Corrected: Removed U+00A0
}

// Implement net.Listener interface methods
func (this *XRUDPListener) Accept() (net.Conn, error) { return this.AcceptXRUDP() }
func (this *XRUDPListener) Close() error {
	this.CloseAllXRUDP()
	return this.conn.Close()
}
func (this *XRUDPListener) Addr() net.Addr { return this.conn.LocalAddr() }

// CloseXRUDP closes a specific XRUDP connection by its remote address string.
func (this *XRUDPListener) CloseXRUDP(addr string) {
	this.lock.Lock()
	defer this.lock.Unlock()
	if rconn, ok := this.xrudpConnMap[addr]; ok {
		delete(this.xrudpConnMap, addr)
		// Also remove from connIDMap if it exists and is the primary CID
		if rconn.xrudp != nil && rconn.xrudp.connID != 0 {
			delete(this.connIDMap, rconn.xrudp.connID)
		}
		rconn.closef = nil // Prevent recursive call
		rconn.Close()
	}
}

// CloseAllXRUDP closes all active XRUDP connections.
func (this *XRUDPListener) CloseAllXRUDP() {
	this.lock.Lock()
	defer this.lock.Unlock()
	for _, rconn := range this.xrudpConnMap {
		rconn.closef = nil // Prevent recursive call
		rconn.Close()
	}
	this.xrudpConnMap = make(map[string]*XRUDPConn)
	this.connIDMap = make(map[uint64]*XRUDPConn) // Reset map
}

// AcceptXRUDP accepts a new XRUDP connection.
func (this *XRUDPListener) AcceptXRUDP() (*XRUDPConn, error) {
	select {
	case c := <-this.newXRUDPConn:
		return c, nil
	case e := <-this.newXRUDPErr:
		return nil, e
	}
}

// run is the main listener loop for incoming UDP packets.
func (this *XRUDPListener) run() {
	data := make([]byte, MAX_PACKET_SIZE) // Use MAX_PACKET_SIZE for buffer
	for {
		n, remoteAddr, err := this.conn.ReadFromUDP(data)
		if err != nil {
			this.CloseAllXRUDP()
			this.newXRUDPErr <- err
			return
		}

		packetData := make([]byte, n)
		copy(packetData, data[:n])

		// Attempt to parse header to get Connection ID and flags
		header, err := parsePacketHeader(packetData)
		if err != nil {
			dbg("Listener: Error parsing incoming packet header from %s: %v. Dropping.", remoteAddr, err)
			continue // Drop malformed packets
		}

		this.lock.RLock()
		var xrudpConn *XRUDPConn
		var ok bool

		// 1. Try to find by Connection ID (for established or migrating connections)
		// Check if CID is present and if it's a known CID for an existing connection.
		if header.flags&FLAG_CID != 0 {
			xrudpConn, ok = this.connIDMap[header.connID]
		}
		// 2. If not found by CID, try by remote address (for initial handshake)
		if !ok {
			xrudpConn, ok = this.xrudpConnMap[remoteAddr.String()]
		}
		this.lock.RUnlock()

		if !ok {
			// This is a new incoming connection (SYN packet)
			if header.packetType == TYPE_CONN_REQ && (header.flags&FLAG_SYN != 0) {
				dbg("Listener: New incoming SYN packet from %s. Creating new XRUDP connection.", remoteAddr.String())
				// Create a new XRUDP instance for this connection (server side)
				// 错误修复：New 函数现在需要三个参数：isServer, connID, ulpSignaler
				newXRUDP := New(true, 0, &DefaultULPSignaler{}) // Server side, CID will be learned from client's SYN // 错误修复：第 122 行，第 27 列
				xrudpConn = NewUnConn(this.conn, remoteAddr, newXRUDP, this.CloseXRUDP)

				this.lock.Lock()
				this.xrudpConnMap[remoteAddr.String()] = xrudpConn
				// Add to connIDMap later, after XRUDP.Input processes the packet and sets its connID.
				this.lock.Unlock()

				this.newXRUDPConn <- xrudpConn // Notify AcceptXRUDP that a new connection is available
			} else {
				dbg("Listener: Received unsolicited packet of type %x from %s before handshake. Dropping.", header.packetType, remoteAddr.String())
				continue // Drop packets that are not SYNs for new connections
			}
		} else {
			// Existing connection, ensure CID is mapped if not already
			this.lock.Lock()
			// If the connection was initially mapped by remoteAddr.String() but now has a CID
			// AND that CID is not yet in connIDMap, add it.
			if header.flags&FLAG_CID != 0 && xrudpConn.xrudp.connID == header.connID {
				if _, cidMapped := this.connIDMap[header.connID]; !cidMapped {
					this.connIDMap[header.connID] = xrudpConn
					dbg("Listener: Mapped existing connection %s to CID %d in connIDMap.", remoteAddr.String(), header.connID)
				}
			}
			this.lock.Unlock()
		}

		// Feed the packet to the appropriate XRUDP connection's input channel
		select {
		case xrudpConn.in <- packetData:
			// Packet sent to connection
		default:
			dbg("Listener: XRUDPConn input channel full for %s, dropping packet.", remoteAddr.String())
		}
	}
}
