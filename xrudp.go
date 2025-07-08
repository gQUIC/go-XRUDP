// xrudp.go
package xrudp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"fmt" // Re-added fmt for error formatting and debugging output
	"log" // 错误修复：导入 log 包
)

// Packet Types (Control Segments - Stream ID 0)
const (
	TYPE_PING     = 0x00 // Ping packet (keep-alive)
	TYPE_EOF      = 0x01 // End of file/stream (graceful shutdown)
	TYPE_CORRUPT  = 0x02 // Corrupted packet detected (error notification)
	TYPE_REQUEST  = 0x03 // Request for missing packets (retransmission request)
	TYPE_MISSING  = 0x04 // Notification of missing packets (informational)
	TYPE_NORMAL   = 0x05 // Normal data packet (payload is application data)
	TYPE_ACK      = 0x06 // Acknowledgment packet
	TYPE_CONN_REQ = 0x07 // Connection request (SYN)
	TYPE_CONN_RSP = 0x08 // Connection response (SYN-ACK)
	TYPE_CONN_CFM = 0x09 // Connection confirm (ACK for handshake)
	TYPE_RST      = 0x0A // Reset connection (abrupt termination)
	TYPE_NUL      = 0x0B // Null segment (keep-alive, from RUDP spec)
	TYPE_TCS      = 0x0C // Transfer Connection State (from RUDP spec)


	// Stream-specific control types
	TYPE_STREAM_FIN   = 0x10 // Graceful stream termination
	TYPE_STREAM_RESET = 0x11 // Abrupt stream reset

	// Flow Control & Connection Management Control Segment Types (can also be Extended Header Fields)
	TYPE_MAX_STREAM_DATA    = 0x20 // Max data offset for a specific stream
	TYPE_MAX_CONNECTION_DATA = 0x21 // Max total data offset for the connection
	TYPE_PATH_CHALLENGE     = 0x30 // Used for path validation
	TYPE_PATH_RESPONSE      = 0x31 // Response to PATH_CHALLENGE
	TYPE_NEW_CONNECTION_ID  = 0x32 // Informs peer about a new Connection ID
	TYPE_RETIRE_CONNECTION_ID = 0x33 // Informs peer to retire a Connection ID
	// 错误修复：添加缺失的 TYPE_STREAM_BLOCKED 和 TYPE_CONN_BLOCKED
	TYPE_STREAM_BLOCKED = 0x40 // Stream blocked by flow control (as a control segment type)
	TYPE_CONN_BLOCKED   = 0x41 // Connection blocked by flow control (as a control segment type)
)

// Extended Header Field Types (TLV) - These are distinct from Packet Types
const (
	EXT_TYPE_0RTT_TOKEN       = 0x01 // Session ticket for 0-RTT
	EXT_TYPE_PATH_UPDATE      = 0x02 // New source IP/Port for connection migration
	EXT_TYPE_MAX_STREAM_DATA  = 0x03 // Max stream data offset (can be in TLV or control segment)
	EXT_TYPE_MAX_CONN_DATA    = 0x04 // Max connection data offset (can be in TLV or control segment)
	EXT_TYPE_STREAM_RESET_CODE = 0x05 // Stream reset with error code
	EXT_TYPE_STREAM_BLOCKED   = 0x06 // Stream blocked by flow control
	EXT_TYPE_CONN_BLOCKED     = 0x07 // Connection blocked by flow control
	EXT_TYPE_NEW_CONNECTION_ID = 0x08 // New Connection ID
	EXT_TYPE_RETIRE_CONNECTION_ID = 0x09 // Retire Connection ID
	EXT_TYPE_TIMESTAMP        = 0x0A // Timestamp for 0-RTT replay protection (if used as a separate field)
)


// Packet Flags (within the first byte of the header)
const (
	FLAG_CID       uint16 = 1 << 0 // Connection ID present
	FLAG_STREAM_ID uint16 = 1 << 1 // Stream ID present (packet carries stream data)
	FLAG_ACK       uint16 = 1 << 2 // ACK field is present/valid
	FLAG_EACK      uint16 = 1 << 3 // Extended ACK field is present/valid
	FLAG_SYN       uint16 = 1 << 4 // SYN packet (connection request)
	FLAG_ACK_ONLY  uint16 = 1 << 5 // ACK only packet (no data payload)
	FLAG_XTN       uint16 = 1 << 6 // Extended Header Fields present (TLV)
	FLAG_CHK       uint16 = 1 << 7 // Checksum covers header and data (from RUDP spec)
	// 错误修复：将 FLAG_RST, FLAG_NUL, FLAG_TCS 的类型从 byte 改为 uint16，以避免溢出
	FLAG_RST       uint16 = 1 << 8 // Reset connection (abrupt termination) // 错误修复：第 72 行，第 24 列
	FLAG_NUL       uint16 = 1 << 9 // Null segment (keep-alive, from RUDP spec) // 错误修复：第 73 行，第 24 列
	FLAG_TCS       uint16 = 1 << 10 // Transfer Connection State (from RUDP spec) // 错误修复：第 74 行，第 24 列
)

// Protocol Parameters (from xrudp_conf.go, for clarity here)
const (
	MAX_MSG_HEAD    = 4                         // Placeholder, actual size depends on flags
	GENERAL_PACKAGE = 1200                      // Recommended MTU for UDP (IPv6 minimum MTU minus headers)
	MAX_UDP_PAYLOAD = 1472                      // Max UDP payload for typical Ethernet MTU (1500 - 20 IP - 8 UDP)
	MAX_PACKET_SIZE = MAX_UDP_PAYLOAD           // Max XRUDP packet size

	// TCS Segment specific lengths/offsets (from RUDP Spec Figure 7)
	TCS_SEGMENT_LENGTH        byte = 12 // Header (6) + Seq Adj Factor (4) + Spare (2)
	TCS_SEQ_ADJ_FACTOR_OFFSET      = 6 // Offset of Seq Adj Factor within TCS payload
	TCS_CONN_IDENTIFIER_OFFSET     = 8 // Offset of Connection Identifier within TCS payload
	TCS_CONN_IDENTIFIER_LENGTH     = 4 // Length of Connection Identifier (32 bits)
)

// Error Codes (from xrudp_conf.go, for clarity here)
const (
	ERROR_NIL int32 = iota
	ERROR_EOF
	ERROR_REMOTE_EOF
	ERROR_CORRUPT
	ERROR_MSG_SIZE
	ERROR_NOT_CONNECTED
	ERROR_INVALID_CID
	ERROR_INVALID_STREAM_ID
	ERROR_0RTT_REPLAY
	ERROR_PATH_VALIDATION_FAILED
	ERROR_FLOW_CONTROL_BLOCKED
	ERROR_CONNECTION_BROKEN // New: Connection explicitly broken
	ERROR_AUTO_RESET_FAILED // New: Auto reset attempts exceeded
)

// Error represents an XRUDP specific error with atomic access.
type Error struct {
	v int32
}

func (e *Error) Load() int32   { return atomic.LoadInt32(&e.v) }
func (e *Error) Store(n int32) { atomic.StoreInt32(&e.v, n) }

func (e *Error) Error() error {
	switch e.Load() {
	case ERROR_EOF:
		return errors.New("EOF")
	case ERROR_REMOTE_EOF:
		return errors.New("remote EOF")
	case ERROR_CORRUPT:
		return errors.New("corrupt")
	case ERROR_MSG_SIZE:
		return errors.New("receive msg size error")
	case ERROR_NOT_CONNECTED:
		return errors.New("not connected")
	case ERROR_INVALID_CID:
		return errors.New("invalid connection ID")
	case ERROR_INVALID_STREAM_ID:
		return errors.New("invalid stream ID")
	case ERROR_0RTT_REPLAY:
		return errors.New("0-RTT replay detected")
	case ERROR_PATH_VALIDATION_FAILED:
		return errors.New("path validation failed")
	case ERROR_FLOW_CONTROL_BLOCKED:
		return errors.New("flow control blocked")
	case ERROR_CONNECTION_BROKEN:
		return errors.New("connection broken")
	case ERROR_AUTO_RESET_FAILED:
		return errors.New("auto reset attempts exceeded, connection failed")
	default:
		return nil
	}
}

// Package represents a raw UDP packet for transmission.
type Package struct {
	Next *Package
	Bts  []byte // Raw bytes of the UDP packet
}

// packageBuffer is an internal helper for building XRUDP packets.
type packageBuffer struct {
	tmp  bytes.Buffer // Underlying buffer for building packet data
	num  int          // Number of packets packed
	head *Package     // Head of the linked list of packed UDP packets
	tail *Package     // Tail of the linked list of packed UDP packets
}

// len returns the current length of the internal buffer.
func (p *packageBuffer) len() int { return p.tmp.Len() }

// reset clears the buffer and resets the packet list.
func (p *packageBuffer) reset() {
	p.tmp.Reset()
	p.num = 0
	p.head = nil
	p.tail = nil
}

// pack finalizes the current buffer content into a Package and adds it to the list.
func (p *packageBuffer) pack() {
	if p.tmp.Len() == 0 { // Only pack if there's content
		return
	}
	// Copy bytes from buffer to avoid issues if buffer is reused later.
	bts := make([]byte, p.tmp.Len())
	copy(bts, p.tmp.Bytes())
	pkg := &Package{Bts: bts}
	if p.head == nil {
		p.head = pkg
		p.tail = pkg
	} else {
		p.tail.Next = pkg // 错误修复：将 .Next 改为 .Next (保持大写，因为 Node 结构体中的 Next 字段是导出的)
		p.tail = pkg
	}
	p.tmp.Reset() // Clear buffer for next packet
	p.num++
}

// writeByte writes a single byte to the internal buffer.
func (p *packageBuffer) writeByte(b byte) {
	p.tmp.WriteByte(b)
}

// writeBytes writes a byte slice to the internal buffer.
func (p *packageBuffer) writeBytes(b []byte) {
	p.tmp.Write(b)
}

// packetHeader stores parsed XRUDP packet header information.
type packetHeader struct {
	flags      uint16 // 错误修复：flags 类型从 byte 改为 uint16
	headerLen  byte   // Total length of the header in bytes
	connID     uint64 // Connection ID (if FLAG_CID is set)
	streamID   uint32 // Stream ID (if FLAG_STREAM_ID is set)
	packetID   uint32 // Unique packet ID within a stream/connection
	ackNum     uint32 // Cumulative ACK number (if FLAG_ACK is set)
	packetType byte   // Type of the packet (e.g., TYPE_NORMAL, TYPE_ACK)
	eackRanges []EACKRange // Extended ACK ranges (if FLAG_EACK is set)
	extFields  []ExtendedHeaderField // Extended Header Fields (if FLAG_XTN is set)
	checksum   uint16 // Checksum field (from RUDP spec)
}

// EACKRange represents a range of missing packets for Extended ACK.
type EACKRange struct {
	Start uint32
	End   uint32
}

// ExtendedHeaderField represents a Type-Length-Value (TLV) field in the header.
type ExtendedHeaderField struct {
	Type   uint8
	Length uint8
	Value  []byte
}

// parsePacketHeader parses the XRUDP packet header from a byte slice.
func parsePacketHeader(bts []byte) (*packetHeader, error) {
	if len(bts) < 6 { // Min RUDP header is 6 octets: Flags (1) + HeaderLen (1) + Sequence# (1) + Ack# (1) + Checksum (2)
		return nil, errors.New("packet too short for minimum RUDP header")
	}

	header := &packetHeader{}
	header.flags = binary.BigEndian.Uint16(bts[0:2]) // 错误修复：flags 现在是 uint16，需要读取 2 字节
	header.headerLen = bts[2] // 错误修复：headerLen 偏移量后移 1 字节

	// Basic sanity check on header length
	if int(header.headerLen) > len(bts) || int(header.headerLen) < 6 { // Min 6 for RUDP header
		return nil, errors.New("declared header length is invalid or exceeds packet length")
	}

	offset := 3 // 错误修复：起始偏移量后移 1 字节 (flags 2字节 + headerLen 1字节)

	// RUDP Spec: Sequence # (1 octet), Ack Number (1 octet)
	// Our current implementation uses uint32 for packetID and ackNum.
	// We will parse 4 bytes for packetID and 4 bytes for ackNum for compatibility with our internal uint32.
	// This deviates slightly from the RUDP spec's 1-octet sequence/ack numbers but aligns with our current code.
	// For strict RUDP compliance, these would need to be 1-byte, and then expanded to uint32.
	// For this task, we assume our existing uint32 usage for packetID and ackNum is the "base".

	// Packet ID (Sequence # in RUDP spec)
	if len(bts) < offset+4 {
		return nil, errors.New("packet too short for Packet ID")
	}
	header.packetID = binary.BigEndian.Uint32(bts[offset : offset+4])
	offset += 4

	// Acknowledgment Number
	if len(bts) < offset+4 {
		return nil, errors.New("packet too short for Acknowledgment Number")
	}
	header.ackNum = binary.BigEndian.Uint32(bts[offset : offset+4])
	offset += 4

	// Checksum (2 octets)
	if len(bts) < offset+2 {
		return nil, errors.New("packet too short for Checksum")
	}
	header.checksum = binary.BigEndian.Uint16(bts[offset : offset+2])
	offset += 2

	// --- Custom XRUDP extensions beyond basic RUDP header ---
	// Our XRUDP has Connection ID, Stream ID, Packet Type, EACK, XTN as optional.
	// The RUDP spec has fixed 6-octet header for data, and specific formats for SYN/EACK/RST/NUL/TCS.
	// We need to adapt this parsing to match our `writePacketHeader` which is more flexible.

	// Packet Type (our TYPE_NORMAL, TYPE_ACK etc. is separate from RUDP's control bits)
	// In RUDP spec, packet type is implicitly derived from control bits (SYN, ACK, RST, NUL, TCS).
	// We will infer our `packetType` based on the flags for compatibility.
	// 错误修复：确保 FLAG_RST, FLAG_NUL, FLAG_TCS 在这里被正确识别
	if header.flags&FLAG_SYN != 0 {
		header.packetType = TYPE_CONN_REQ // Or TYPE_CONN_RSP if ACK is also set
	} else if header.flags&FLAG_ACK_ONLY != 0 && header.flags&FLAG_ACK != 0 { // Our ACK_ONLY flag
		header.packetType = TYPE_ACK
	} else if header.flags&FLAG_RST != 0 { // RUDP spec RST bit
		header.packetType = TYPE_RST
	} else if header.flags&FLAG_NUL != 0 { // RUDP spec NUL bit
		header.packetType = TYPE_NUL
	} else if header.flags&FLAG_TCS != 0 { // RUDP spec TCS bit
		header.packetType = TYPE_TCS
	} else {
		header.packetType = TYPE_NORMAL // Default to normal data if no other specific type
	}


	// Connection ID (our extension)
	if header.flags&FLAG_CID != 0 {
		if len(bts) < offset+8 {
			return nil, errors.New("packet too short for Connection ID (XRUDP extension)")
		}
		header.connID = binary.BigEndian.Uint64(bts[offset : offset+8])
		offset += 8
	}

	// Stream ID (our extension)
	if header.flags&FLAG_STREAM_ID != 0 {
		if len(bts) < offset+4 {
			return nil, errors.New("packet too short for Stream ID (XRUDP extension)")
		}
		header.streamID = binary.BigEndian.Uint32(bts[offset : offset+4])
		offset += 4
	}

	// Extended ACK Ranges (EACK) (our extension, RUDP spec has different EACK format)
	if header.flags&FLAG_EACK != 0 {
		// Our EACK format: count (1 byte) + (start, end) pairs (8 bytes each)
		if len(bts) < offset+1 {
			return nil, errors.New("packet too short for EACK count (XRUDP extension)")
		}
		eackCount := int(bts[offset])
		offset += 1
		if len(bts) < offset+(eackCount*8) {
			return nil, errors.New("packet too short for EACK ranges (XRUDP extension)")
		}
		for i := 0; i < eackCount; i++ {
			start := binary.BigEndian.Uint32(bts[offset : offset+4])
			end := binary.BigEndian.Uint32(bts[offset+4 : offset+8])
			header.eackRanges = append(header.eackRanges, EACKRange{Start: start, End: end})
			offset += 8
		}
	}

	// Extended Header Fields (XTN) (our extension)
	if header.flags&FLAG_XTN != 0 {
		// Read TLV fields until end of headerLen
		for offset < int(header.headerLen) {
			if len(bts) < offset+2 { // Need at least Type and Length bytes
				return nil, errors.New("malformed extended header fields (type/length missing, XRUDP extension)")
			}
			extType := bts[offset]
			extLength := bts[offset+1]
			offset += 2

			if len(bts) < offset+int(extLength) {
				return nil, errors.New("malformed extended header field (value missing, XRUDP extension)")
			}
			extValue := bts[offset : offset+int(extLength)]
			header.extFields = append(header.extFields, ExtendedHeaderField{
				Type:   extType,
				Length: extLength,
				Value:  extValue,
			})
			offset += int(extLength)
		}
	}

	// Final check to ensure we've consumed exactly the declared header length
	if byte(offset) != header.headerLen {
		return nil, errors.New("parsed header length mismatch with declared header length")
	}

	return header, nil
}

// writePacketHeader constructs the header bytes for an XRUDP packet based on the header struct.
// This function combines RUDP spec's fixed header with our flexible extensions.
func writePacketHeader(header *packetHeader, dataPayload []byte, enableChecksum bool) ([]byte, error) {
	var headerBytes bytes.Buffer // Use bytes.Buffer for efficient byte building
	var flags uint16 = 0 // 错误修复：flags 类型从 byte 改为 uint16
	var headerLen byte = 0 // Will calculate based on fields

	// Apply RUDP spec flags
	if header.packetType == TYPE_CONN_REQ || header.packetType == TYPE_CONN_RSP {
		flags |= FLAG_SYN
	}
	if header.flags&FLAG_ACK != 0 || header.packetType == TYPE_CONN_RSP || header.packetType == TYPE_CONN_CFM || header.packetType == TYPE_NORMAL || header.packetType == TYPE_NUL || header.packetType == TYPE_RST {
		flags |= FLAG_ACK // ACK bit is always set for data, NUL, RST, and SYN-ACK
	}
	// 错误修复：确保 FLAG_RST, FLAG_NUL, FLAG_TCS 在这里被正确设置
	if header.packetType == TYPE_RST {
		flags |= FLAG_RST
	}
	if header.packetType == TYPE_NUL {
		flags |= FLAG_NUL
	}
	if header.packetType == TYPE_TCS {
		flags |= FLAG_TCS
	}
	if enableChecksum { // CHK bit from RUDP spec
		flags |= FLAG_CHK
	}

	// Our XRUDP extensions flags
	if header.connID != 0 {
		flags |= FLAG_CID
	}
	if header.streamID != 0 {
		flags |= FLAG_STREAM_ID
	}
	if len(header.eackRanges) > 0 {
		flags |= FLAG_EACK
	}
	if len(header.extFields) > 0 {
		flags |= FLAG_XTN
	}
	if header.flags&FLAG_ACK_ONLY != 0 { // For pure ACK packets
		flags |= FLAG_ACK_ONLY
	}

	// Calculate header length (fixed RUDP part first)
	headerLen = 3 // 错误修复：Flags (2) + HeaderLen (1)
	headerLen += 4 // Packet ID (Sequence #)
	headerLen += 4 // Ack Number
	headerLen += 2 // Checksum

	// Calculate length for our XRUDP extensions
	if flags&FLAG_CID != 0 {
		headerLen += 8 // Connection ID
	}
	if flags&FLAG_STREAM_ID != 0 {
		headerLen += 4 // Stream ID
	}
	if flags&FLAG_EACK != 0 {
		headerLen += 1 + byte(len(header.eackRanges)*8) // EACK count + ranges
	}
	if flags&FLAG_XTN != 0 {
		for _, ef := range header.extFields {
			headerLen += 2 + ef.Length // Type (1) + Length (1) + Value (Length)
		}
	}

	// Write fixed RUDP header fields
	flagsBytes := make([]byte, 2) // 错误修复：flags 现在是 uint16，需要写入 2 字节
	binary.BigEndian.PutUint16(flagsBytes, flags)
	headerBytes.Write(flagsBytes)
	headerBytes.WriteByte(headerLen)

	// Write Sequence # (our packetID)
	packetIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(packetIDBytes, header.packetID)
	headerBytes.Write(packetIDBytes)

	// Write Ack Number (our ackNum)
	ackNumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ackNumBytes, header.ackNum)
	headerBytes.Write(ackNumBytes)

	// Placeholder for Checksum (will be calculated and put at the end of header building)
	checksumPlaceholder := make([]byte, 2)
	headerBytes.Write(checksumPlaceholder) // Write 2 zero bytes for now

	// Write our XRUDP extension fields
	if flags&FLAG_CID != 0 {
		connIDBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(connIDBytes, header.connID)
		headerBytes.Write(connIDBytes)
	}
	if flags&FLAG_STREAM_ID != 0 {
		streamIDBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(streamIDBytes, header.streamID)
		headerBytes.Write(streamIDBytes)
	}

	if flags&FLAG_EACK != 0 {
		headerBytes.WriteByte(byte(len(header.eackRanges)))
		for _, r := range header.eackRanges {
			startBytes := make([]byte, 4)
			endBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(startBytes, r.Start)
			binary.BigEndian.PutUint32(endBytes, r.End)
			headerBytes.Write(startBytes)
			headerBytes.Write(endBytes)
		}
	}

	if flags&FLAG_XTN != 0 {
		for _, ef := range header.extFields {
			headerBytes.WriteByte(ef.Type)
			headerBytes.WriteByte(ef.Length)
			headerBytes.Write(ef.Value)
		}
	}

	finalHeaderBytes := headerBytes.Bytes()

	// Calculate checksum over the header (and data if CHK bit is set)
	var checksumData []byte
	if enableChecksum {
		checksumData = append(finalHeaderBytes, dataPayload...)
	} else {
		checksumData = finalHeaderBytes
	}
	// 错误修复：校验和计算时，需要将校验和字段暂时清零
	// 找到校验和字段在 finalHeaderBytes 中的位置 (flags 2字节 + headerLen 1字节 + packetID 4字节 + ackNum 4字节 = 11字节)
	// 校验和是 2 字节，所以从 11 到 13
	checksumOffset := 2 + 1 + 4 + 4 // flags (2) + headerLen (1) + packetID (4) + ackNum (4) = 11
	
	// 临时保存原始校验和字段的值
	originalChecksumBytes := make([]byte, 2)
	copy(originalChecksumBytes, finalHeaderBytes[checksumOffset:checksumOffset+2])
	
	// 在计算校验和之前，将校验和字段清零
	binary.BigEndian.PutUint16(finalHeaderBytes[checksumOffset:checksumOffset+2], 0)

	calculatedChecksum := calculateChecksum(checksumData)
	binary.BigEndian.PutUint16(finalHeaderBytes[checksumOffset:checksumOffset+2], calculatedChecksum) // Update the placeholder

	// 错误修复：恢复原始校验和字段的值，以防后续代码需要原始数据
	copy(finalHeaderBytes[checksumOffset:checksumOffset+2], originalChecksumBytes)


	// Final check to ensure the length matches.
	if byte(len(finalHeaderBytes)) != headerLen {
		return nil, errors.New("calculated header length mismatch during writing")
	}

	return finalHeaderBytes, nil
}


// Node represents a packet/segment in a linked list.
type Node struct {
	id   uint32 // Packet ID or Stream Sequence Number (offset)
	next *Node // 错误修复：将 Next 改为 next (小写) // 错误修复：第 522 行，第 10 列
	data []byte
	t    time.Time // Timestamp for RTO/expiration
	retransmissions uint8 // New: Retransmission count for this packet
}

// List implements a simple singly linked list (used for send/receive queues, history).
type List struct {
	head *Node
	tail *Node
	num  int // Number of nodes in the list
}

// put adds a new node to the end of the list.
func (l *List) put(id uint32, data []byte) *Node {
	n := &Node{id: id, data: data, t: time.Now()}
	if l.head == nil {
		l.head = n
		l.tail = n
	} else {
		l.tail.next = n // 错误修复：将 .Next 改为 .next // 错误修复：第 538 行，第 10 列
		l.tail = n
	}
	l.num++
	return n
}

// putList appends another list to the end of this list.
func (l *List) putList(nl *List) {
	if nl == nil || nl.head == nil {
		return
	}
	if l.head == nil {
		l.head = nl.head
		l.tail = nl.tail
	} else {
		l.tail.next = nl.head // 错误修复：将 .Next 改为 .next // 错误修复：第 538 行，第 10 列
		l.tail = nl.tail
	}
	l.num += nl.num
}

// get retrieves a node by its ID.
func (l *List) get(id uint32) *Node {
	for n := l.head; n != nil; n = n.next {
		if n.id == id {
			return n
		}
	}
	return nil
}

// del removes a node by its ID and returns it.
func (l *List) del(id uint32) *Node {
	var prev *Node
	for n := l.head; n != nil; n = n.next {
		if n.id == id {
			if prev == nil {
				l.head = n.next
			} else {
				prev.next = n.next
			}
			if n == l.tail {
				l.tail = prev
			}
			n.next = nil // Decouple removed node
			l.num--
			return n
		}
		prev = n
	}
	return nil
}

// StreamState defines the state of an XRUDP stream.
type StreamState int

const (
	StreamStateIdle StreamState = iota
	StreamStateOpen
	StreamStateHalfClosedLocal  // Local endpoint has sent FIN
	StreamStateHalfClosedRemote // Remote endpoint has sent FIN
	StreamStateClosing          // Both sent FIN, waiting for ACKs
	StreamStateClosed           // All data acknowledged or reset
	StreamStateReset            // Abruptly reset
)

// Stream represents a single logical stream within an XRUDP connection.
type Stream struct {
	sync.Mutex // Protects stream state

	ID uint32 // Stream Identifier
	State StreamState

	// Send state
	sendQueue       *List  // Data waiting to be sent (application -> protocol)
	sendHistory     *List  // Sent data waiting for ACK (for retransmission)
	sendOffset      uint32 // Next byte offset to send on this stream
	lastSentPacketID uint32 // Last packet ID sent on this stream
	sendFlowWindow  uint32 // Peer's advertised flow window for this stream
	bytesInFlight   uint32 // Bytes sent but not yet acknowledged on this stream

	// Receive state
	recvQueue       *List  // In-order received data waiting for application
	recvMissing     *List  // Out-of-order received data
	recvOffset      uint32 // Next expected byte offset to receive on this stream
	recvFlowWindow  uint32 // Our advertised flow window for this stream
	lastRecvPacketID uint32 // Last packet ID received (used for EACK generation)

	// Control channels for communication with XRUDP core
	reqSendAgain chan EACKRange // Request retransmission for missing SNs (EACK range)
	addSendAgain chan EACKRange // Add SNs to be retransmitted (from peer's requests)

	// Stream specific error
	error *Error
}

// newStream creates a new Stream instance.
func newStream(id uint32, initialSendWindow, initialRecvWindow uint32) *Stream {
	return &Stream{
		ID:           id,
		State:        StreamStateOpen, // Streams start in Open state
		sendQueue:    new(List),
		sendHistory:  new(List),
		recvQueue:    new(List),
		recvMissing:  new(List),
		reqSendAgain: make(chan EACKRange, 256), // Buffered channel for EACK requests
		addSendAgain: make(chan EACKRange, 256), // Buffered channel for retransmission requests
		sendFlowWindow: initialSendWindow,
		recvFlowWindow: initialRecvWindow,
		error:        new(Error),
	}
}

// SendStreamData adds data to the stream's send queue, respecting flow control.
func (s *Stream) SendStreamData(bts []byte) (n int, err error) {
	s.Lock()
	defer s.Unlock()

	if s.error.Load() != ERROR_NIL {
		return 0, s.error.Error()
	}
	if s.State >= StreamStateHalfClosedLocal {
		return 0, errors.New("stream already half-closed locally or closed")
	}
	if len(bts) == 0 {
		return 0, nil
	}

	// Check stream flow control
	if s.bytesInFlight+uint32(len(bts)) > s.sendFlowWindow {
		dbg("Stream %d blocked by flow control. Bytes in flight: %d, Window: %d", s.ID, s.bytesInFlight, s.sendFlowWindow)
		s.error.Store(ERROR_FLOW_CONTROL_BLOCKED) // Set stream-specific error
		return 0, errors.New("stream flow control blocked")
	}

	s.sendQueue.put(s.sendOffset, bts) // Stream ID is byte offset
	s.sendOffset += uint32(len(bts))
	s.bytesInFlight += uint32(len(bts))
	dbg("Stream %d added %d bytes, offset: %d, total in flight: %d", s.ID, s.sendOffset-uint32(len(bts)), s.bytesInFlight) // 错误修复：dbg 参数数量匹配
	return len(bts), nil
}

// RecvStreamData retrieves data from the stream's receive queue.
func (s *Stream) RecvStreamData(bts []byte) (n int, err error) {
	s.Lock()
	defer s.Unlock()

	if s.error.Load() != ERROR_NIL {
		return 0, s.error.Error()
	}

	// Pop data only if it's the next expected sequence number (offset)
	m := s.recvQueue.head
	if m == nil || m.id != s.recvOffset {
		return 0, nil // No data or out-of-order data
	}

	// Pop the message
	s.recvQueue.del(s.recvOffset) // Pop by ID (offset)
	
	copy(bts, m.data)
	n = len(m.data)
	s.recvOffset += uint32(n) // Advance receive offset

	dbg("Stream %d received %d bytes, offset: %d, next expected: %d", s.ID, n, m.id, s.recvOffset)

	// Potentially update receive flow window here and signal to send MAX_STREAM_DATA
	s.updateRecvFlowWindow()

	return n, nil
}

// insertMessage inserts a received message into the stream's receive queue.
// Handles out-of-order delivery.
func (s *Stream) insertMessage(packetID uint32, streamOffset uint32, bts []byte) {
	s.Lock()
	defer s.Unlock()

	if s.error.Load() != ERROR_NIL {
		dbg("Stream %d: Cannot insert message, stream is in error state: %v", s.ID, s.error.Error())
		return
	}
	if s.State >= StreamStateHalfClosedRemote { // Cannot receive more data if remote has closed
		dbg("Stream %d: Cannot insert message, remote side is closed.", s.ID)
		return
	}

	// Check if this packet is a duplicate or already processed
	if streamOffset < s.recvOffset {
		dbg("Stream %d: Already received data up to offset %d, discarding old offset %d.", s.ID, s.recvOffset, streamOffset)
		return
	}
	if s.recvMissing.get(streamOffset) != nil || s.recvQueue.get(streamOffset) != nil {
		dbg("Stream %d: Duplicate offset %d, discarding.", s.ID, streamOffset)
		return
	}

	// Check receive flow control window
	if streamOffset+uint32(len(bts)) > s.recvFlowWindow {
		dbg("Stream %d: Received data beyond flow window. Offset %d, len %d, Window %d. Dropping.", s.ID, streamOffset, len(bts), s.recvFlowWindow)
		// In a real implementation, this might trigger a connection error or a flow control violation.
		return
	}

	// Insert new message
	if streamOffset == s.recvOffset {
		// In-order packet, add to recvQueue
		s.recvQueue.put(streamOffset, bts)
		dbg("Stream %d: Inserted in-order offset %d, length %d. Queue size: %d", s.ID, streamOffset, len(bts), s.recvQueue.num)
		// Try to re-process any previously missing packets that are now in order
		s.checkMissing(true)
	} else {
		// Out-of-order packet, add to recvMissing
		s.recvMissing.put(streamOffset, bts)
		dbg("Stream %d: Inserted out-of-order offset %d, length %d. Missing queue size: %d", s.ID, streamOffset, len(bts), s.recvMissing.num)
		s.checkMissing(false) // Check for new gaps after adding out-of-order
	}

	// Update last received packet ID for EACK generation
	if packetID > s.lastRecvPacketID {
		s.lastRecvPacketID = packetID
	}
}

// checkMissing identifies gaps in the received sequence and requests them.
// If `force` is true, it processes `recvMissing` to fill `recvQueue`.
// If `force` is false, it just identifies gaps for retransmission requests.
func (s *Stream) checkMissing(force bool) {
	// First, try to move consecutive packets from recvMissing to recvQueue
	if force {
		for {
			node := s.recvMissing.get(s.recvOffset)
			if node != nil {
				s.recvMissing.del(s.recvOffset)
				s.recvQueue.put(node.id, node.data)
				s.recvOffset += uint32(len(node.data)) // Advance offset
				dbg("Stream %d: Filled gap with offset %d from missing queue. New recvOffset: %d", s.ID, node.id, s.recvOffset)
			} else {
				break
			}
		}
	}

	// Now, identify any new gaps for requesting using EACK
	var missingRanges []EACKRange
	currentExpected := s.recvOffset
	
	// Get all out-of-order offsets and sort them
	var sortedMissingOffsets []uint32
	for n := s.recvMissing.head; n != nil; n = n.next {
		sortedMissingOffsets = append(sortedMissingOffsets, n.id)
	}
	// Simple sort for prototype. In production, use a sorted data structure.
	for i := 0; i < len(sortedMissingOffsets); i++ {
		for j := i + 1; j < len(sortedMissingOffsets); j++ {
			if sortedMissingOffsets[i] > sortedMissingOffsets[j] {
				sortedMissingOffsets[i], sortedMissingOffsets[j] = sortedMissingOffsets[j], sortedMissingOffsets[i]
			}
		}
	}

	for _, offset := range sortedMissingOffsets {
		if offset > currentExpected {
			// Gap found: from currentExpected to offset-1 are missing
			missingRanges = append(missingRanges, EACKRange{Start: currentExpected, End: offset - 1})
		}
		// 错误修复：确保在访问 `s.recvMissing.get(offset).data` 之前检查 `get` 的返回值
		node := s.recvMissing.get(offset)
		if node != nil {
			currentExpected = offset + uint32(len(node.data)) // Move past this packet's data
		} else {
			// This case should ideally not happen if sortedMissingOffsets only contains valid IDs from recvMissing
			// But as a safeguard, if a node is unexpectedly nil, advance to next offset.
			currentExpected = offset + 1
		}
	}

	// Queue EACK requests
	for _, r := range missingRanges {
		select {
		case s.reqSendAgain <- r:
			dbg("Stream %d: Queued EACK request for missing range %d-%d", s.ID, r.Start, r.End)
		default:
			dbg("Stream %d: reqSendAgain channel full, skipping EACK request for %d-%d", s.ID, r.Start, r.End)
		}
	}
}

// updateRecvFlowWindow updates the receiver's flow window and signals to send MAX_STREAM_DATA.
func (s *Stream) updateRecvFlowWindow() {
	// Simple window update: always keep window open by initial size beyond current offset
	newWindow := s.recvOffset + s.recvFlowWindow // This is a simple additive update
	// In a real system, this would be based on available buffer space.
	if newWindow > s.recvFlowWindow { // Only send update if window actually increased
		s.recvFlowWindow = newWindow
		dbg("Stream %d: Updated receive flow window to %d", s.ID, s.recvFlowWindow)
		// Signal to XRUDP core to send a MAX_STREAM_DATA frame to the peer
		// This signal needs to be picked up by XRUDP.Update()
	}
}

// SessionTicket represents a cached 0-RTT session ticket.
type SessionTicket struct {
	Ticket    []byte    // Opaque encrypted blob
	IssueTime time.Time // When the ticket was issued
	Nonce     uint64    // A nonce for replay protection (corrected from uint66)
}

// PathChallenge represents an outstanding path validation challenge.
type PathChallenge struct {
	Challenge uint64    // The random challenge value
	SentTime  time.Time // When the challenge was sent
	Retries   int       // Number of retries
}

// SYNParameters holds the negotiable parameters exchanged during SYN.
// Corresponds to Figure 2 in the RUDP specification.
type SYNParameters struct {
	Version                  uint8
	MaxOutstandingSegs       uint16
	OptionFlags              uint16
	MaxSegmentSize           uint16
	RetransmissionTimeoutValue uint16 // In milliseconds
	CumulativeAckTimeoutValue uint16 // In milliseconds
	NullSegmentTimeoutValue    uint16 // In milliseconds
	TransferStateTimeoutValue  uint16 // In milliseconds
	MaxRetrans                 uint8
	MaxCumAck                  uint8
	MaxOutOfSeq                uint8
	MaxAutoReset               uint8
	ConnectionIdentifier       uint32 // 32 bits in length
}

// ToBytes serializes SYNParameters to a byte slice.
func (s *SYNParameters) ToBytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, s.Version)
	binary.Write(buf, binary.BigEndian, s.MaxOutstandingSegs)
	binary.Write(buf, binary.BigEndian, s.OptionFlags)
	binary.Write(buf, binary.BigEndian, s.MaxSegmentSize)
	binary.Write(buf, binary.BigEndian, s.RetransmissionTimeoutValue)
	binary.Write(buf, binary.BigEndian, s.CumulativeAckTimeoutValue)
	binary.Write(buf, binary.BigEndian, s.NullSegmentTimeoutValue)
	binary.Write(buf, binary.BigEndian, s.TransferStateTimeoutValue)
	binary.Write(buf, binary.BigEndian, s.MaxRetrans)
	binary.Write(buf, binary.BigEndian, s.MaxCumAck)
	binary.Write(buf, binary.BigEndian, s.MaxOutOfSeq)
	binary.Write(buf, binary.BigEndian, s.MaxAutoReset)
	binary.Write(buf, binary.BigEndian, s.ConnectionIdentifier)
	return buf.Bytes()
}

// FromBytes deserializes SYNParameters from a byte slice.
func (s *SYNParameters) FromBytes(data []byte) error {
	if len(data) < 22 { // Total size of all fields
		return errors.New("SYN parameters payload too short")
	}
	buf := bytes.NewReader(data)
	binary.Read(buf, binary.BigEndian, &s.Version)
	binary.Read(buf, binary.BigEndian, &s.MaxOutstandingSegs)
	binary.Read(buf, binary.BigEndian, &s.OptionFlags)
	binary.Read(buf, binary.BigEndian, &s.MaxSegmentSize)
	binary.Read(buf, binary.BigEndian, &s.RetransmissionTimeoutValue)
	binary.Read(buf, binary.BigEndian, &s.CumulativeAckTimeoutValue)
	binary.Read(buf, binary.BigEndian, &s.NullSegmentTimeoutValue)
	binary.Read(buf, binary.BigEndian, &s.TransferStateTimeoutValue)
	binary.Read(buf, binary.BigEndian, &s.MaxRetrans)
	binary.Read(buf, binary.BigEndian, &s.MaxCumAck)
	binary.Read(buf, binary.BigEndian, &s.MaxOutOfSeq)
	binary.Read(buf, binary.BigEndian, &s.MaxAutoReset)
	binary.Read(buf, binary.BigEndian, &s.ConnectionIdentifier)
	return nil
}

// ULPSignaler defines the interface for signaling events to the Upper Layer Protocol.
type ULPSignaler interface {
	OnConnectionOpen(connID uint64, remoteAddr net.Addr)
	OnConnectionRefused(connID uint64, remoteAddr net.Addr, reason error)
	OnConnectionClosed(connID uint64, remoteAddr net.Addr, reason error)
	OnConnectionFailure(connID uint64, remoteAddr net.Addr, reason error)
	OnConnectionAutoReset(connID uint64, remoteAddr net.Addr, reason error)
}

// DefaultULPSignaler provides a basic logging implementation of ULPSignaler.
type DefaultULPSignaler struct{}

func (d *DefaultULPSignaler) OnConnectionOpen(connID uint64, remoteAddr net.Addr) {
	log.Printf("[ULP_SIGNAL] Connection %d opened with %s", connID, remoteAddr)
}
func (d *DefaultULPSignaler) OnConnectionRefused(connID uint64, remoteAddr net.Addr, reason error) {
	log.Printf("[ULP_SIGNAL] Connection %d refused by %s: %v", connID, remoteAddr, reason)
}
func (d *DefaultULPSignaler) OnConnectionClosed(connID uint64, remoteAddr net.Addr, reason error) {
	log.Printf("[ULP_SIGNAL] Connection %d closed with %s: %v", connID, remoteAddr, reason)
}
func (d *DefaultULPSignaler) OnConnectionFailure(connID uint64, remoteAddr net.Addr, reason error) {
	log.Printf("[ULP_SIGNAL] Connection %d failed with %s: %v", connID, remoteAddr, reason)
}
func (d *DefaultULPSignaler) OnConnectionAutoReset(connID uint64, remoteAddr net.Addr, reason error) {
	log.Printf("[ULP_SIGNAL] Connection %d auto reset with %s: %v", connID, remoteAddr, reason)
}


// XRUDP implements the core Reliable UDP Protocol logic.
type XRUDP struct {
	sync.RWMutex // Protects connection state

	conf *XRUDPConfig // Configuration parameters

	connID        uint64       // Connection ID, 0 for unestablished
	remoteAddr    *net.UDPAddr // Primary remote address for this connection
	currentRemoteAddr *net.UDPAddr // The actual remote address packets are currently sent to (can change with migration)

	isServer      bool         // True if this is a server-side instance
	handshakeDone bool         // True if connection handshake is complete
	state         ConnectionState // Current state of the connection

	// Packet numbering for connection-level control packets
	sendPacketNum uint32 // Next ID for outgoing packets
	recvPacketNum uint32 // Last packet ID received (cumulative ACK for connection-level)

	// Streams
	streams        map[uint32]*Stream // Map StreamID to Stream object
	nextClientStreamID uint32 // Next available client-initiated stream ID
	nextServerStreamID uint32 // Next available server-initiated stream ID

	// Connection-level flow control
	connSendFlowWindow uint32 // Peer's advertised connection flow window
	connRecvFlowWindow uint32 // Our advertised connection flow window
	connBytesInFlight  uint32 // Total bytes sent across all streams not yet acknowledged

	// Packet retransmission and ACK management
	sendHistory *List // History of sent connection-level packets (e.g., control packets)
	recvAck     map[uint32]struct{} // Set of received ACKs
	sendAck     map[uint32]struct{} // Set of ACKs to be sent

	// 0-RTT related
	sessionTickets []*SessionTicket // Stored 0-RTT tickets for this peer
	replayNonces   map[uint64]time.Time // For 0-RTT replay protection (nonce -> timestamp)

	// Path management (for connection migration)
	activeCIDs        map[uint64]struct{} // Set of CIDs currently in use by this connection
	pathChallengesSent map[uint64]*PathChallenge // Outstanding path challenges (challenge -> PathChallenge struct)
	pathValidated     bool // True if current path is validated

	// Internal control channels
	queueControl chan []byte // Channel to queue control segments for sending
	error        *Error      // Connection-level error state
	close        chan struct{} // Signal to close internal goroutines

    // 新增字段：用于 TLS 加密套件
    crypto *CryptoSuite

    // 新增字段：表示连接是否已建立或处于活动状态
    connected int32 // 使用 atomic.Int32 来安全地管理连接状态，0 表示未连接，1 表示已连接

	// 新增字段：RUDP 规范中的定时器和计数器
	lastRecvTime         time.Time // Last time any packet was received
	lastSentTime         time.Time // Last time any packet was sent (for client NUL timer)
	retransmissionCount  uint8     // Consecutive retransmissions for the current RTO period
	cumulativeAckCount   uint8     // Number of unacknowledged segments received without sending ACK
	outOfSequenceCount   uint8     // Number of out-of-sequence segments received without sending EACK
	autoResetCount       uint8     // Consecutive auto resets without connection opening

	// Timers for RUDP spec (managed by Update loop)
	cumulativeAckTimer *time.Timer // Timer for Cumulative Ack Timeout Value
	nullSegmentTimer   *time.Timer // Client-side Null Segment Timer
	serverNullSegmentTimer *time.Timer // Server-side Null Segment Timer
	transferStateTimer *time.Timer // Transfer State Timeout Value timer

	ulpSignaler ULPSignaler // Interface for signaling to Upper Layer Protocol

	negotiatedParams *SYNParameters // Stores the final negotiated parameters
}

// ConnectionState defines the state of an XRUDP connection.
type ConnectionState int

const (
	StateDisconnected ConnectionState = iota
	StateHandshake
	StateEstablished
	StateClosing
	StateClosed
)

// New creates a new XRUDP instance.
func New(isServer bool, connID uint64, ulpSignaler ULPSignaler) *XRUDP {
	config := NewDefaultConfig()
	// 错误修复：在创建 XRUDP 实例之前设置包级别的 debug 标志
	SetDebugFlag(config.Debug) // 错误修复：第 332 行，第 2 列
	x := &XRUDP{
		conf: config,
		connID:            connID,
		isServer:          isServer,
		state:             StateDisconnected,
		streams:           make(map[uint32]*Stream),
		sendHistory:       new(List),
		recvAck:           make(map[uint32]struct{}),
		sendAck:           make(map[uint32]struct{}),
		sessionTickets:    make([]*SessionTicket, 0, config.MaxZeroRTTSessionTickets),
		replayNonces:      make(map[uint64]time.Time),
		activeCIDs:        make(map[uint64]struct{}),
		pathChallengesSent: make(map[uint64]*PathChallenge),
		connSendFlowWindow: config.InitialConnFlowWindow,
		connRecvFlowWindow: config.InitialConnFlowWindow,
		queueControl:      make(chan []byte, 256), // Buffered channel for control segments
		error:             new(Error),
		close:             make(chan struct{}),
		crypto:            NewCryptoSuite(), // 初始化 CryptoSuite
		
		// Initialize new RUDP spec fields
		lastRecvTime:         time.Now(),
		lastSentTime:         time.Now(),
		retransmissionCount:  0,
		cumulativeAckCount:   0,
		outOfSequenceCount:   0,
		autoResetCount:       0,
		ulpSignaler:          ulpSignaler, // Set the ULP signaler
		negotiatedParams:     &SYNParameters{}, // Will be filled during handshake
	}

	// Initialize stream ID counters
	if isServer {
		x.nextClientStreamID = 1 // Client-initiated streams start odd
		x.nextServerStreamID = 2 // Server-initiated streams start even
	} else {
		x.nextClientStreamID = 1
		x.nextServerStreamID = 2
	}
	
	// Add initial CID if provided
	if connID != 0 {
		x.activeCIDs[connID] = struct{}{}
	}

	// Set initial connected state to false
	x.SetConnected(false)

	// Initialize timers (they will be started/reset in Update/handleControlSegment)
	x.cumulativeAckTimer = time.NewTimer(x.conf.CumulativeAckTimeoutValue)
	x.cumulativeAckTimer.Stop() // Stop initially
	x.nullSegmentTimer = time.NewTimer(x.conf.NullSegmentTimeoutValue)
	x.nullSegmentTimer.Stop() // Stop initially
	x.serverNullSegmentTimer = time.NewTimer(x.conf.NullSegmentTimeoutValue * 2) // Server's timer is twice client's
	x.serverNullSegmentTimer.Stop() // Stop initially
	x.transferStateTimer = time.NewTimer(x.conf.TransferStateTimeoutValue)
	x.transferStateTimer.Stop() // Stop initially

	return x
}

// Close closes the XRUDP instance.
func (x *XRUDP) Close() error {
	x.Lock()
	defer x.Unlock()

	if x.state == StateClosed {
		return nil // Already closed
	}

	previousState := x.state
	x.state = StateClosing
	x.error.Store(ERROR_EOF) // Set connection error
	x.SetConnected(false) // Set connected state to false on close

	// Send RST to peer (best effort)
	x.sendRST()

	// Signal internal goroutines to stop
	select {
	case <-x.close: // Already closed or signal sent
	default:
		close(x.close)
	}

	// Clean up resources (channels, maps)
	for _, s := range x.streams {
		s.Lock()
		s.error.Store(ERROR_REMOTE_EOF) // Stream EOF
		// Close stream-specific channels if they exist
		s.Unlock()
	}
	x.streams = nil
	x.sendHistory = nil
	x.recvAck = nil
	x.sendAck = nil
	x.sessionTickets = nil
	x.replayNonces = nil
	x.activeCIDs = nil
	x.pathChallengesSent = nil
	// Do not close x.queueControl here, as sendRST might still be writing to it.
	// It will be garbage collected when no longer referenced.

	// Stop all timers
	x.cumulativeAckTimer.Stop()
	x.nullSegmentTimer.Stop()
	x.serverNullSegmentTimer.Stop()
	x.transferStateTimer.Stop()

	// ULP Signal: Connection Closed
	if x.ulpSignaler != nil {
		if previousState == StateEstablished || previousState == StateClosing {
			x.ulpSignaler.OnConnectionClosed(x.connID, x.RemoteAddr(), x.error.Error())
		} else if previousState == StateHandshake {
			x.ulpSignaler.OnConnectionRefused(x.connID, x.RemoteAddr(), x.error.Error())
		}
	}

	x.state = StateClosed // Final state
	dbg("XRUDP connection %d closed. Reason: %v", x.connID, x.error.Error())
	return nil
}

// GetStream retrieves a stream by its ID. Creates it if it doesn't exist.
// This method ensures thread-safe access and creation of streams.
func (x *XRUDP) GetStream(id uint32) *Stream {
	x.RLock()
	s, ok := x.streams[id]
	x.RUnlock()
	if !ok {
		x.Lock()
		defer x.Unlock()
		// Double check in case it was created while waiting for lock
		s, ok = x.streams[id]
		if !ok {
			// Determine initial window sizes from config
			initialStreamSendWindow := x.conf.InitialStreamFlowWindow
			initialStreamRecvWindow := x.conf.InitialStreamFlowWindow
			s = newStream(id, initialStreamSendWindow, initialStreamRecvWindow)
			x.streams[id] = s
			dbg("Created new stream: %d", id)
		}
	}
	return s
}

// Send sends data on a specific stream.
func (x *XRUDP) Send(streamID uint32, bts []byte) (n int, err error) {
	x.Lock() // Use Lock for Send to update lastSentTime and connBytesInFlight
	defer x.Unlock()

	if x.error.Load() != ERROR_NIL {
		return 0, x.error.Error()
	}
	if x.state != StateEstablished {
		return 0, errors.New("connection not established")
	}

	stream := x.GetStream(streamID)
	if stream == nil {
		return 0, errors.New("stream not found") // Should not happen with GetStream
	}

	// Check connection-level flow control
	if x.connBytesInFlight+uint32(len(bts)) > x.connSendFlowWindow {
		dbg("Connection %d blocked by flow control. Bytes in flight: %d, Window: %d", x.connID, x.connBytesInFlight, x.connSendFlowWindow)
		// Signal connection blocked to peer (e.g., via a control frame)
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, x.connSendFlowWindow)
		x.queueControlSegment(TYPE_MAX_CONNECTION_DATA, payload, (x.negotiatedParams.OptionFlags&OPT_CHK_BIT) != 0) // 错误修复：添加 enableChecksum 参数
		return 0, errors.New("connection flow control blocked")
	}

	n, err = stream.SendStreamData(bts)
	if err == nil {
		x.connBytesInFlight += uint32(n)
		x.lastSentTime = time.Now() // Update last sent time
		// Reset client-side null segment timer if active
		if !x.isServer && x.conf.NullSegmentTimeoutValue > 0 {
			x.nullSegmentTimer.Reset(x.conf.NullSegmentTimeoutValue)
		}
	}
	return n, err
}

// Recv receives data from a specific stream.
func (x *XRUDP) Recv(streamID uint32, bts []byte) (n int, err error) {
	x.RLock()
	connErr := x.error.Load() // 错误修复：connErr 现在是 int32 类型
	x.RUnlock()

	if connErr != ERROR_NIL {
		return 0, x.error.Error() // 错误修复：直接调用 x.error.Error() // 错误修复：第 1212 行，第 21 列
	}

	stream := x.GetStream(streamID)
	if stream == nil {
		return 0, errors.New("stream not found")
	}

	n, err = stream.RecvStreamData(bts)
	if err == nil && n > 0 {
		// Update connection-level receive flow window
		x.Lock()
		// This is a simplified update. In a real system, it would be based on
		// actual consumption and available buffer space.
		x.Unlock()
		// Signal to send MAX_CONNECTION_DATA frame to the peer if window increased significantly
		x.queueFlowControlUpdate()
	}
	return n, err
}

// Update processes internal timers and generates outgoing packets.
func (x *XRUDP) Update() *Package {
	x.Lock()
	defer x.Unlock()

	if x.error.Load() != ERROR_NIL {
		return nil
	}
	if x.state == StateClosed || x.state == StateDisconnected {
		return nil // No updates for closed or disconnected states
	}

	// Check for connection-level broken conditions and auto-reset
	x.checkBrokenConnectionAndAutoReset()

	// Clear expired send history for all streams and connection-level history
	x.clearExpiredSendHistory()

	var tmp packageBuffer
	tmp.reset()

	// 1. Process queued control segments
	x.processQueuedControlSegments(&tmp)

	// 2. Process ACKs to send (connection-level and stream-level EACKs)
	x.processOutgoingAcks(&tmp)

	// 3. Process retransmissions (connection-level and stream-level)
	x.processRetransmissions(&tmp)

	// 4. Process new application data to send from streams
	x.processStreamOutgoingData(&tmp)

	// 5. Handle RUDP spec timers
	x.handleRUDPSpecTimers(&tmp)

	// Final pack if anything is left in the buffer
	if tmp.len() > 0 {
		tmp.pack()
	}

	return tmp.head
}

// Input processes an incoming raw XRUDP packet.
func (x *XRUDP) Input(bts []byte, remoteAddr *net.UDPAddr) error {
	x.Lock()
	defer x.Unlock()

	if x.error.Load() != ERROR_NIL {
		dbg("Input: Connection %d is in error state: %v. Dropping packet.", x.connID, x.error.Error())
		return x.error.Error()
	}

	// Update last received time
	x.lastRecvTime = time.Now()
	// Reset server-side null segment timer if active
	if x.isServer && x.conf.NullSegmentTimeoutValue > 0 {
		x.serverNullSegmentTimer.Reset(x.conf.NullSegmentTimeoutValue * 2)
	}

	// Parse Common XRUDP Header
	header, err := parsePacketHeader(bts)
	if err != nil {
		dbg("Input: Failed to parse XRUDP header from %s: %v", remoteAddr, err)
		x.error.Store(ERROR_CORRUPT)
		return err
	}

	// Verify Checksum if CHK bit is set
	if header.flags&FLAG_CHK != 0 {
		// Re-calculate checksum over header + payload
		// The `parsePacketHeader` already extracted the checksum, so we need to verify.
		// Temporarily zero out the checksum field in the raw bytes for calculation
		originalChecksum := header.checksum
		// 错误修复：校验和字段的偏移量需要根据新的 header 结构来计算
		checksumOffset := 2 + 1 + 4 + 4 // flags (2) + headerLen (1) + packetID (4) + ackNum (4) = 11
		binary.BigEndian.PutUint16(bts[checksumOffset:checksumOffset+2], 0) // Zero out checksum field for calculation
		
		calculatedChecksum := calculateChecksum(bts[:int(header.headerLen)]) // Header checksum
		if len(bts) > int(header.headerLen) {
			calculatedChecksum = calculateChecksum(bts) // Header + Data checksum
		}
		binary.BigEndian.PutUint16(bts[checksumOffset:checksumOffset+2], originalChecksum) // Restore original checksum

		if calculatedChecksum != originalChecksum {
			dbg("Input: Checksum mismatch for packet ID %d from %s. Calculated: %x, Received: %x. Dropping.", header.packetID, remoteAddr, calculatedChecksum, originalChecksum)
			x.error.Store(ERROR_CORRUPT)
			return errors.New("checksum mismatch")
		}
	} else {
		// Only header checksum is implied by RUDP spec if CHK bit is zero.
		// Our `parsePacketHeader` already extracted the checksum.
		// We could verify header-only checksum here if needed. For now, assume it's implicitly verified by header parsing.
	}


	// Validate Connection ID
	if header.flags&FLAG_CID != 0 {
		if x.connID == 0 { // If our side doesn't have a CID yet, adopt the incoming one (e.g., client receiving SYN-ACK)
			x.connID = header.connID
			x.activeCIDs[x.connID] = struct{}{}
			dbg("Input: Adopted CID %d from incoming packet from %s.", x.connID, remoteAddr)
		} else if header.connID != x.connID {
			// This could be a connection migration attempt or an invalid packet.
			// For now, treat as invalid CID. A real implementation would handle this more gracefully.
			dbg("Input: Mismatched Connection ID: received %d, expected %d. From: %s. Dropping.", header.connID, x.connID, remoteAddr)
			x.error.Store(ERROR_INVALID_CID)
			return errors.New("invalid connection ID")
		}
	} else if x.connID != 0 && x.state == StateEstablished {
		// If our connection has a CID, but the incoming packet doesn't (and it's not a handshake packet),
		// it's likely an error unless it's a very specific context.
		dbg("Input: Packet without CID received for established connection with CID %d. Dropping.", x.connID)
		x.error.Store(ERROR_INVALID_CID)
		return errors.New("missing connection ID for established connection")
	}

	// Handle connection migration: if remoteAddr changed, initiate path validation
	if x.currentRemoteAddr == nil || x.currentRemoteAddr.String() != remoteAddr.String() {
		dbg("Input: Received packet from new remote address: %s. Current: %s", remoteAddr.String(), x.currentRemoteAddr.String())
		// If this is a new path for an existing connection, initiate validation
		if x.connID != 0 && x.state == StateEstablished {
			x.initiatePathValidation(remoteAddr)
		}
		// Temporarily update currentRemoteAddr, will switch fully upon validation success
		x.currentRemoteAddr = remoteAddr
	}

	// Process Extended Header Fields
	for _, extField := range header.extFields {
		x.handleExtendedHeaderField(extField, remoteAddr)
	}

	// Acknowledge the received packet ID for connection-level ACKs
	x.addSendAck(header.packetID)

	// Process payload based on Stream ID presence
	payload := bts[int(header.headerLen):]
	if header.flags&FLAG_STREAM_ID != 0 {
		// Stream Data Packet
		stream := x.GetStream(header.streamID)
		if stream == nil {
			dbg("Input: Received stream data for unknown stream ID %d, discarding.", header.streamID)
			// Optionally send STREAM_RESET for unknown stream
			x.queueControlSegment(TYPE_STREAM_RESET, binary.BigEndian.AppendUint32(nil, header.streamID), (x.negotiatedParams.OptionFlags&OPT_CHK_BIT) != 0) // 错误修复：添加 enableChecksum 参数
			return errors.New("unknown stream ID")
		}
		// Stream data packets use their own sequence numbers (offsets)
		stream.insertMessage(header.packetID, header.packetID, payload) // Assuming PacketID is also StreamOffset for simplicity
		// Update out-of-sequence counter if needed
		if header.packetID > stream.recvOffset { // If out-of-order
			x.outOfSequenceCount++
			if x.outOfSequenceCount >= x.conf.MaxOutOfSeq {
				stream.checkMissing(false) // Force EACK
				x.outOfSequenceCount = 0 // Reset counter
			}
		}
	} else {
		// Control Packet (Stream ID 0 or implicit for connection-level)
		x.handleControlSegment(header, payload, remoteAddr)
	}

	// Reset cumulative ACK counter if an ACK was sent or enough data received
	if header.flags&FLAG_ACK != 0 { // If peer sent an ACK
		x.cumulativeAckCount = 0
		x.cumulativeAckTimer.Reset(x.conf.CumulativeAckTimeoutValue) // Restart timer
	} else {
		x.cumulativeAckCount++
		if x.cumulativeAckCount >= x.conf.MaxCumAck {
			x.processOutgoingAcks(&packageBuffer{}) // Force sending ACKs
			x.cumulativeAckCount = 0
		}
	}


	return nil
}

// processQueuedControlSegments processes control segments queued internally.
func (x *XRUDP) processQueuedControlSegments(tmp *packageBuffer) {
	for {
		select {
		case segment := <-x.queueControl:
			x.sendPacketNum++
			controlHeader := &packetHeader{
				flags:      0, // Control segments typically don't have stream ID flag
				connID:     x.connID,
				packetID:   x.sendPacketNum,
				ackNum:     x.recvPacketNum, // Piggyback cumulative ACK
				packetType: segment[0],      // First byte is control type
			}
			// Set specific flags based on control type (RUDP spec)
			if controlHeader.packetType == TYPE_CONN_REQ || controlHeader.packetType == TYPE_CONN_RSP {
				controlHeader.flags |= FLAG_SYN
			}
			if controlHeader.packetType == TYPE_ACK || controlHeader.packetType == TYPE_CONN_RSP || controlHeader.packetType == TYPE_CONN_CFM || controlHeader.packetType == TYPE_NUL || controlHeader.packetType == TYPE_RST {
				controlHeader.flags |= FLAG_ACK
			}
			if controlHeader.packetType == TYPE_RST {
				controlHeader.flags |= FLAG_RST
			}
			if controlHeader.packetType == TYPE_NUL {
				controlHeader.flags |= FLAG_NUL
			}
			if controlHeader.packetType == TYPE_TCS {
				controlHeader.flags |= FLAG_TCS
			}
			if controlHeader.packetType == TYPE_ACK || controlHeader.packetType == TYPE_CONN_CFM || controlHeader.packetType == TYPE_NUL || controlHeader.packetType == TYPE_RST {
				controlHeader.flags |= FLAG_ACK_ONLY // Our internal flag for pure ACK packets
			}

			// Checksum bit based on negotiation
			enableChecksum := false
			if x.negotiatedParams != nil {
				enableChecksum = (x.negotiatedParams.OptionFlags & OPT_CHK_BIT) != 0
			} else {
				// During handshake, use default config's CHK setting
				enableChecksum = (x.conf.OptionFlags & OPT_CHK_BIT) != 0
			}

			x.packPacket(tmp, controlHeader, segment[1:], enableChecksum)
		default:
			return
		}
	}
}

// processOutgoingAcks processes ACKs to be sent.
func (x *XRUDP) processOutgoingAcks(tmp *packageBuffer) {
	// Checksum bit based on negotiation
	enableChecksum := false
	if x.negotiatedParams != nil {
		enableChecksum = (x.negotiatedParams.OptionFlags & OPT_CHK_BIT) != 0
	} else {
		// During handshake, use default config's CHK setting
		enableChecksum = (x.conf.OptionFlags & OPT_CHK_BIT) != 0
	}

	// Process connection-level ACKs
	for ackID := range x.sendAck {
		x.packAck(tmp, ackID, nil, enableChecksum) // Pack a connection-level ACK
		delete(x.sendAck, ackID)
	}

	// Process stream-level EACKs
	for _, s := range x.streams {
		s.Lock()
		x.processStreamOutgoingEacks(s, tmp, enableChecksum)
		s.Unlock()
	}
}

// processStreamOutgoingEacks processes EACKs for a specific stream.
func (x *XRUDP) processStreamOutgoingEacks(s *Stream, tmp *packageBuffer, enableChecksum bool) {
	var eackRanges []EACKRange
	// Collect EACK ranges from stream's reqSendAgain channel
	for {
		select {
		case r := <-s.reqSendAgain:
			eackRanges = append(eackRanges, r)
		default:
			break
		}
	}

	if len(eackRanges) > 0 {
		x.sendPacketNum++
		header := &packetHeader{
			flags:      FLAG_EACK | FLAG_ACK | FLAG_STREAM_ID, // Set EACK, ACK, and Stream ID flags
			connID:     x.connID,
			streamID:   s.ID,
			packetID:   x.sendPacketNum,
			ackNum:     s.recvOffset, // Cumulative stream ACK (next expected offset)
			packetType: TYPE_ACK, // EACKs are a type of ACK
			eackRanges: eackRanges,
		}
		x.packPacket(tmp, header, nil, enableChecksum) // EACKs are in header, no separate payload
		dbg("Packed EACK for stream %d with %d ranges.", s.ID, len(eackRanges))
	}
}

// processRetransmissions handles retransmissions for connection-level and streams.
func (x *XRUDP) processRetransmissions(tmp *packageBuffer) {
	// Checksum bit based on negotiation
	enableChecksum := false
	if x.negotiatedParams != nil {
		enableChecksum = (x.negotiatedParams.OptionFlags & OPT_CHK_BIT) != 0
	} else {
		enableChecksum = (x.conf.OptionFlags & OPT_CHK_BIT) != 0
	}

	// Connection-level retransmissions (e.g., handshake packets, control messages)
	// Iterate through sendHistory, check for timeouts (RTO), and retransmit.
	// Increment retransmissionCount for each retransmitted packet.
	for n := x.sendHistory.head; n != nil; n = n.next {
		if time.Since(n.t) > x.conf.RetransmissionTimeoutValue {
			if n.retransmissions < x.conf.MaxRetrans {
				x.sendPacketNum++
				header := &packetHeader{
					flags:      0, // Flags depend on original packet type
					connID:     x.connID,
					packetID:   x.sendPacketNum, // New packet ID for retransmission
					ackNum:     x.recvPacketNum,
					packetType: TYPE_NORMAL, // Placeholder, should be original type
				}
				// Re-pack original header flags and type if possible
				// For simplicity, assuming control segments here
				if len(n.data) > 0 {
					header.packetType = n.data[0] // Assuming first byte of data is original control type
				}
				
				x.packPacket(tmp, header, n.data, enableChecksum)
				n.t = time.Now() // Reset timestamp for this retransmission
				n.retransmissions++
				x.retransmissionCount++ // Increment connection-level retransmission counter
				dbg("Connection: Retransmitted packet ID %d (original ID %d), retransmissions: %d", header.packetID, n.id, n.retransmissions)
			} else {
				dbg("Connection: Packet ID %d reached max retransmissions. Marking connection broken.", n.id)
				x.error.Store(ERROR_CONNECTION_BROKEN)
				return // Stop processing retransmissions, connection is broken
			}
		}
	}

	// Stream-level retransmissions (from peer requests)
	for _, s := range x.streams {
		s.Lock()
		for {
			select {
			case r := <-s.addSendAgain: // This is a stream-level retransmission request from peer
				x.retransmitStreamData(tmp, s, r, enableChecksum)
			default:
				break
			}
		}
		s.Unlock()
	}
}

// retransmitStreamData retransmits data for a given stream and range.
func (x *XRUDP) retransmitStreamData(tmp *packageBuffer, s *Stream, r EACKRange, enableChecksum bool) {
	s.Lock()
	defer s.Unlock()

	var retransmittedCount int
	// Iterate through stream's sendHistory to find packets in the range
	for n := s.sendHistory.head; n != nil; n = n.next {
		// Assuming n.id here is the stream offset (sequence number)
		if n.id >= r.Start && n.id <= r.End {
			if n.retransmissions < x.conf.MaxRetrans {
				x.sendPacketNum++
				header := &packetHeader{
					flags:      FLAG_STREAM_ID | FLAG_ACK, // Stream data packet, with ACK piggybacked
					connID:     x.connID,
					streamID:   s.ID,
					packetID:   x.sendPacketNum, // New packet ID for retransmission
					ackNum:     s.recvOffset,    // Piggyback stream cumulative ACK
					packetType: TYPE_NORMAL,
				}
				x.packPacket(tmp, header, n.data, enableChecksum)
				n.t = time.Now() // Reset timestamp for this retransmission
				n.retransmissions++
				x.retransmissionCount++ // Increment connection-level retransmission counter
				retransmittedCount++
				dbg("Stream %d: Retransmitted offset %d (packet ID %d) for range %d-%d, retransmissions: %d", s.ID, n.id, header.packetID, r.Start, r.End, n.retransmissions)
			} else {
				dbg("Stream %d: Packet offset %d reached max retransmissions. Marking connection broken.", s.ID, n.id)
				x.error.Store(ERROR_CONNECTION_BROKEN)
				return // Stop processing retransmissions, connection is broken
			}
		}
		if n.id > r.End { // Optimization: if history is sorted by ID
			break
		}
	}
	if retransmittedCount == 0 {
		dbg("Stream %d: No data found for retransmission in range %d-%d", s.ID, r.Start, r.End)
	}
}

// processStreamOutgoingData processes new application data from streams.
func (x *XRUDP) processStreamOutgoingData(tmp *packageBuffer) {
	// Checksum bit based on negotiation
	enableChecksum := false
	if x.negotiatedParams != nil {
		enableChecksum = (x.negotiatedParams.OptionFlags & OPT_CHK_BIT) != 0
	} else {
		enableChecksum = (x.conf.OptionFlags & OPT_CHK_BIT) != 0
	}

	for streamID, s := range x.streams {
		s.Lock()
		for {
			node := s.sendQueue.head // Get next message from stream's send queue
			if node == nil {
				break
			}

			// Check stream flow control
			if s.bytesInFlight+uint32(len(node.data)) > s.sendFlowWindow {
				dbg("Stream %d blocked by flow control (send window). Bytes in flight: %d, Window: %d", s.ID, s.bytesInFlight, s.sendFlowWindow)
				// Signal Stream Blocked to peer (if not already)
				x.queueControlSegment(TYPE_STREAM_BLOCKED, binary.BigEndian.AppendUint32(nil, s.ID), enableChecksum) // 错误修复：添加 enableChecksum 参数 // 错误修复：第 1633 行，第 27 列
				break
			}

			// Check connection-level flow control
			if x.connBytesInFlight+uint32(len(node.data)) > x.connSendFlowWindow {
				dbg("Connection %d blocked by flow control (connection window). Bytes in flight: %d, Window: %d", x.connID, x.connBytesInFlight, x.connSendFlowWindow)
				// Signal Connection Blocked to peer
				x.queueControlSegment(TYPE_CONN_BLOCKED, nil, enableChecksum) // 错误修复：添加 enableChecksum 参数 // 错误修复：第 1641 行，第 27 列
				break
			}

			s.sendQueue.del(node.id) // Remove from send queue
			s.sendHistory.put(node.id, node.data) // Add to send history for ACK tracking

			x.sendPacketNum++ // Increment global packet ID
			header := &packetHeader{
				flags:      FLAG_STREAM_ID | FLAG_ACK, // Stream data packet, with ACK piggybacked
				connID:     x.connID,
				streamID:   streamID,
				packetID:   x.sendPacketNum,
				ackNum:     s.recvOffset, // Piggyback stream cumulative ACK
				packetType: TYPE_NORMAL,
			}
			x.packPacket(tmp, header, node.data, enableChecksum)

			s.bytesInFlight += uint32(len(node.data))
			x.connBytesInFlight += uint32(len(node.data))
			x.lastSentTime = time.Now() // Update last sent time

			dbg("Stream %d: Sent data packet ID %d, offset %d, len %d. Stream bytes in flight: %d, Conn bytes in flight: %d",
				streamID, header.packetID, node.id, len(node.data), s.bytesInFlight, x.connBytesInFlight)

			if tmp.len() > GENERAL_PACKAGE {
				tmp.pack()
			}
		}
		s.Unlock()
	}
}

// handleRUDPSpecTimers manages RUDP-specific timers (Null, Cumulative ACK, Transfer State).
func (x *XRUDP) handleRUDPSpecTimers(tmp *packageBuffer) {
	// Null Segment Timer (Keep-alive)
	if !x.isServer && x.conf.NullSegmentTimeoutValue > 0 { // Client-side
		select {
		case <-x.nullSegmentTimer.C:
			dbg("Client Null Segment Timer expired. Sending NUL segment.")
			x.sendPacketNum++
			x.packControlSegment(tmp, TYPE_NUL, x.sendPacketNum, nil, (x.negotiatedParams.OptionFlags&OPT_CHK_BIT) != 0)
			x.nullSegmentTimer.Reset(x.conf.NullSegmentTimeoutValue) // Reset timer
		default:
			// Timer not expired or already handled
		}
	} else if x.isServer && x.conf.NullSegmentTimeoutValue > 0 { // Server-side
		select {
		case <-x.serverNullSegmentTimer.C:
			dbg("Server Null Segment Timer expired. Connection considered broken.")
			x.error.Store(ERROR_CONNECTION_BROKEN)
			return // Trigger connection broken handling
		default:
			// Timer not expired or already handled
		}
	}

	// Cumulative ACK Timer
	select {
	case <-x.cumulativeAckTimer.C:
		if x.cumulativeAckCount > 0 || x.hasOutOfOrderPackets() {
			dbg("Cumulative ACK Timer expired. Forcing ACK/EACK send.")
			x.processOutgoingAcks(tmp)
			x.cumulativeAckCount = 0 // Reset counter after sending
		}
		x.cumulativeAckTimer.Reset(x.conf.CumulativeAckTimeoutValue) // Reset timer
	default:
		// Timer not expired or already handled
	}

	// Transfer State Timer
	select {
	case <-x.transferStateTimer.C:
		if x.error.Load() == ERROR_CONNECTION_BROKEN {
			dbg("Transfer State Timer expired. Performing Auto Reset.")
			x.performAutoReset(tmp)
		}
	default:
		// Timer not expired or already handled
	}
}

// hasOutOfOrderPackets checks if any stream has out-of-order packets.
func (x *XRUDP) hasOutOfOrderPackets() bool {
	for _, s := range x.streams {
		s.Lock()
		if s.recvMissing.num > 0 {
			s.Unlock()
			return true
		}
		s.Unlock()
	}
	return false
}


// checkBrokenConnectionAndAutoReset checks for conditions that break the connection
// and initiates auto-reset or full reset.
func (x *XRUDP) checkBrokenConnectionAndAutoReset() {
	// Condition 1: Retransmission Count Exceeded
	if x.retransmissionCount >= x.conf.MaxRetrans {
		dbg("Connection %d: Max retransmissions (%d) exceeded. Marking broken.", x.connID, x.conf.MaxRetrans)
		x.error.Store(ERROR_CONNECTION_BROKEN)
	}

	// Condition 2: Server's Null Segment Timer expires (handled in handleRUDPSpecTimers)
	// If x.error is already ERROR_CONNECTION_BROKEN, proceed with handling.

	if x.error.Load() == ERROR_CONNECTION_BROKEN {
		if x.conf.TransferStateTimeoutValue > 0 {
			// Notify ULP of connection failure and start Transfer State Timer
			if x.ulpSignaler != nil {
				x.ulpSignaler.OnConnectionFailure(x.connID, x.RemoteAddr(), x.error.Error())
			}
			x.transferStateTimer.Reset(x.conf.TransferStateTimeoutValue)
			dbg("Connection %d: Declared broken. Transfer State Timer started for %v.", x.connID, x.conf.TransferStateTimeoutValue)
		} else {
			// Transfer State Timeout Value is zero, perform auto reset immediately
			dbg("Connection %d: Declared broken. Transfer State Timeout is zero. Performing immediate Auto Reset.", x.connID)
			x.performAutoReset(&packageBuffer{}) // Pass an empty buffer for immediate action
		}
	}
}

// performAutoReset executes the auto reset logic.
func (x *XRUDP) performAutoReset(tmp *packageBuffer) {
	x.autoResetCount++
	if x.autoResetCount > x.conf.MaxAutoReset {
		dbg("Connection %d: Max auto resets (%d) exceeded. Performing full reset.", x.connID, x.conf.MaxAutoReset)
		x.error.Store(ERROR_AUTO_RESET_FAILED)
		if x.ulpSignaler != nil {
			x.ulpSignaler.OnConnectionAutoReset(x.connID, x.RemoteAddr(), x.error.Error())
		}
		x.Close() // Close the connection permanently
		return
	}

	dbg("Connection %d: Performing Auto Reset. Attempt %d/%d.", x.connID, x.autoResetCount, x.conf.MaxAutoReset)

	// ULP Signal: Connection Auto Reset
	if x.ulpSignaler != nil {
		x.ulpSignaler.OnConnectionAutoReset(x.connID, x.RemoteAddr(), errors.New("auto reset initiated"))
	}

	// Flush all queues
	x.sendHistory = new(List)
	x.recvAck = make(map[uint32]struct{})
	x.sendAck = make(map[uint32]struct{})
	x.connBytesInFlight = 0
	for _, s := range x.streams {
		s.Lock()
		s.sendQueue = new(List)
		s.sendHistory = new(List)
		s.recvQueue = new(List)
		s.recvMissing = new(List)
		s.bytesInFlight = 0
		s.sendOffset = 0
		s.recvOffset = 0
		s.State = StreamStateOpen // Reset stream state
		s.error.Store(ERROR_NIL)
		s.Unlock()
	}

	// Reset initial sequence numbers (randomly pick new ones)
	x.sendPacketNum = uint32(generateConnectionID()) // 错误修复：将 uint64 转换为 uint32 // 错误修复：第 1805 行，第 20 列
	x.recvPacketNum = 0 // Reset peer's last received ACK

	// Re-negotiate connection (if REUSE bit is not set, otherwise use old params)
	// For simplicity, we'll always re-send SYN-ACK/ACK for re-negotiation.
	// The `negotiatedParams` will be updated during this process.
	if !x.isServer {
		// Client initiates new SYN
		x.state = StateHandshake
		x.sendConnRequest()
	} else {
		// Server waits for client's SYN, but can send SYN-ACK if it has client's old CID
		// For now, server just resets and waits for client SYN.
		x.state = StateDisconnected // Reset to disconnected, wait for new SYN-REQ
	}

	x.error.Store(ERROR_NIL) // Clear connection error after reset
	x.handshakeDone = false
	x.SetConnected(false) // Not connected until new handshake completes
	x.retransmissionCount = 0 // Reset retransmission counter
	x.cumulativeAckCount = 0
	x.outOfSequenceCount = 0

	// Stop transfer state timer if it was running
	x.transferStateTimer.Stop()
}

// packPacket constructs a full XRUDP packet (header + payload) and adds it to the buffer.
func (x *XRUDP) packPacket(tmp *packageBuffer, header *packetHeader, payload []byte, enableChecksum bool) {
	headerBytes, err := writePacketHeader(header, payload, enableChecksum) // Pass payload for checksum calculation
	if err != nil {
		dbg("Error writing packet header: %v", err)
		return
	}

	// Calculate total packet size
	totalSize := len(headerBytes) + len(payload)
	if totalSize > MAX_PACKET_SIZE {
		dbg("Packet size %d exceeds MAX_PACKET_SIZE %d. Dropping or fragmenting.", totalSize, MAX_PACKET_SIZE)
		// In a real implementation, this would trigger fragmentation.
		return
	}

	// If current packet buffer is too large to add this, pack it first.
	if tmp.len()+totalSize > GENERAL_PACKAGE {
		tmp.pack()
	}

	// Write header and payload
	tmp.writeBytes(headerBytes)
	if payload != nil {
		tmp.writeBytes(payload)
	}

	dbg("Packed packet ID %d, type %x, len %d. Current buffer len: %d", header.packetID, header.packetType, totalSize, tmp.len())
}

// packControlSegment constructs a control segment and adds it to the buffer.
func (x *XRUDP) packControlSegment(tmp *packageBuffer, pType byte, packetID uint32, payload []byte, enableChecksum bool) {
	header := &packetHeader{
		flags:      0, // Control segments typically don't have stream ID flag
		connID:     x.connID,
		packetID:   packetID,
		ackNum:     x.recvPacketNum, // Piggyback cumulative ACK
		packetType: pType,
	}
	// Set specific flags based on control type (RUDP spec)
	if pType == TYPE_CONN_REQ || pType == TYPE_CONN_RSP {
		header.flags |= FLAG_SYN
	}
	if pType == TYPE_ACK || pType == TYPE_CONN_RSP || pType == TYPE_CONN_CFM || pType == TYPE_NORMAL || pType == TYPE_NUL || pType == TYPE_RST {
		header.flags |= FLAG_ACK
	}
	if pType == TYPE_RST {
		header.flags |= FLAG_RST
	}
	if pType == TYPE_NUL {
		header.flags |= FLAG_NUL
	}
	if pType == TYPE_TCS {
		header.flags |= FLAG_TCS
	}
	if pType == TYPE_ACK || pType == TYPE_CONN_CFM || pType == TYPE_NUL || pType == TYPE_RST {
		header.flags |= FLAG_ACK_ONLY // Our internal flag for pure ACK packets
	}

	x.packPacket(tmp, header, payload, enableChecksum)
}

// packAck packs an ACK packet for the given packet ID.
func (x *XRUDP) packAck(tmp *packageBuffer, ackID uint32, extFields []ExtendedHeaderField, enableChecksum bool) {
	x.sendPacketNum++ // Increment packet ID for the ACK packet itself
	header := &packetHeader{
		flags:      FLAG_ACK, // Set ACK flag
		connID:     x.connID,
		packetID:   x.sendPacketNum,
		ackNum:     ackID, // The ID of the packet being acknowledged
		packetType: TYPE_ACK,
		extFields:  extFields, // Optional extended fields (e.g., for EACK in header)
	}
	// If it's a pure ACK with no data, set ACK_ONLY flag
	if len(extFields) == 0 { // Simplistic check for ACK_ONLY
		header.flags |= FLAG_ACK_ONLY
	}
	x.packPacket(tmp, header, nil, enableChecksum) // ACK packets typically have no payload
	dbg("Packed ACK for ID %d (packet ID %d)", ackID, header.packetID)
}

// clearExpiredSendHistory removes expired packets from connection-level and stream-level send histories.
func (x *XRUDP) clearExpiredSendHistory() {
	// Connection-level history
	x.clearListExpired(x.sendHistory, x.conf.ExpiredTick)

	// Stream-level histories
	for _, s := range x.streams {
		s.Lock()
		x.clearListExpired(s.sendHistory, x.conf.ExpiredTick)
		s.Unlock()
	}
}

// clearListExpired removes nodes from a List that are older than the expiration duration.
func (x *XRUDP) clearListExpired(l *List, expiration time.Duration) {
	for l.head != nil && time.Since(l.head.t) > expiration {
		l.head = l.head.next
		l.num--
	}
	if l.head == nil {
		l.tail = nil
	}
}

// handleExtendedHeaderField processes an Extended Header Field.
func (x *XRUDP) handleExtendedHeaderField(field ExtendedHeaderField, remoteAddr *net.UDPAddr) {
	switch field.Type {
	case EXT_TYPE_0RTT_TOKEN:
		if x.isServer {
			x.process0RTTSessionTicket(field.Value, remoteAddr)
		} else {
			ticket, err := x.parseSessionTicket(field.Value)
			if err != nil {
				dbg("Failed to parse 0-RTT Session Ticket: %v", err)
				return
			}
			x.addSessionTicket(ticket)
			dbg("Received 0-RTT Session Ticket from server.")
		}
	case EXT_TYPE_PATH_UPDATE:
		if len(field.Value) < 6 {
			dbg("Received malformed PATH_UPDATE field.")
			return
		}
		newIP := net.IP(field.Value[:len(field.Value)-2])
		newPort := binary.BigEndian.Uint16(field.Value[len(field.Value)-2:])
		newAddr := &net.UDPAddr{IP: newIP, Port: int(newPort)}
		dbg("Received PATH_UPDATE from peer: %s", newAddr.String())
		if x.connID != 0 && x.state == StateEstablished {
			x.initiatePathValidation(newAddr)
		}
	case EXT_TYPE_MAX_STREAM_DATA:
		if len(field.Value) < 8 {
			dbg("Received malformed MAX_STREAM_DATA field.")
			return
		}
		streamID := binary.BigEndian.Uint32(field.Value[:4])
		maxOffset := binary.BigEndian.Uint32(field.Value[4:8])
		stream := x.GetStream(streamID)
		if stream != nil {
			stream.Lock()
			stream.sendFlowWindow = maxOffset
			stream.Unlock()
			dbg("Stream %d: Updated send flow window to %d", streamID, maxOffset)
		}
	case EXT_TYPE_MAX_CONN_DATA:
		if len(field.Value) < 4 {
			dbg("Received malformed MAX_CONNECTION_DATA field.")
			return
		}
		maxOffset := binary.BigEndian.Uint32(field.Value[:4])
		x.Lock()
		x.connSendFlowWindow = maxOffset
		x.Unlock()
		dbg("Connection: Updated send flow window to %d", maxOffset)
	case EXT_TYPE_STREAM_RESET_CODE:
		if len(field.Value) < 8 {
			dbg("Received malformed STREAM_RESET_CODE field.")
			return
		}
		streamID := binary.BigEndian.Uint32(field.Value[:4])
		errorCode := binary.BigEndian.Uint32(field.Value[4:8])
		stream := x.GetStream(streamID)
		if stream != nil {
			stream.Lock()
			stream.State = StreamStateReset
			stream.error.Store(int32(errorCode))
			dbg("Stream %d: Reset with error code %d", streamID, errorCode)
			stream.sendQueue.head = nil; stream.sendQueue.tail = nil; stream.sendQueue.num = 0
			stream.recvQueue.head = nil; stream.recvQueue.tail = nil; stream.recvQueue.num = 0
			stream.sendHistory.head = nil; stream.sendHistory.tail = nil; stream.sendHistory.num = 0
			stream.recvMissing.head = nil; stream.recvMissing.tail = nil; stream.recvMissing.num = 0
			stream.Unlock()
		}
	case EXT_TYPE_STREAM_BLOCKED:
		if len(field.Value) < 4 {
			dbg("Received malformed STREAM_BLOCKED field.")
			return
		}
		streamID := binary.BigEndian.Uint32(field.Value[:4])
		dbg("Stream %d: Peer reports being blocked by flow control.", streamID)
	case EXT_TYPE_CONN_BLOCKED:
		dbg("Connection: Peer reports being blocked by flow control.")
	case EXT_TYPE_NEW_CONNECTION_ID:
		if len(field.Value) < 8 {
			dbg("Received malformed NEW_CONNECTION_ID field.")
			return
		}
		newCID := binary.BigEndian.Uint64(field.Value[:8])
		x.activeCIDs[newCID] = struct{}{}
		dbg("Received New Connection ID from peer: %d", newCID)
	case EXT_TYPE_RETIRE_CONNECTION_ID:
		if len(field.Value) < 8 {
			dbg("Received malformed RETIRE_CONNECTION_ID field.")
			return
		}
		retireCID := binary.BigEndian.Uint64(field.Value[:8])
		delete(x.activeCIDs, retireCID)
		dbg("Received Retire Connection ID from peer: %d", retireCID)
	case EXT_TYPE_TIMESTAMP:
		if len(field.Value) < 8 {
			dbg("Received malformed TIMESTAMP field.")
			return
		}
		tsNano := binary.BigEndian.Uint64(field.Value[:8])
		dbg("Received timestamp: %d", tsNano)
	default:
		dbg("Unknown Extended Header Field Type: %x, Length: %d", field.Type, field.Length)
	}
}

// handleControlSegment processes a control segment.
func (x *XRUDP) handleControlSegment(header *packetHeader, payload []byte, remoteAddr *net.UDPAddr) {
	if len(payload) == 0 {
		dbg("Received empty control segment for packet ID %d.", header.packetID)
		return
	}

	controlType := payload[0]
	actualPayload := payload[1:]

	switch controlType {
	case TYPE_CONN_REQ: // Client SYN
		if x.isServer && x.state == StateDisconnected {
			var clientParams SYNParameters
			if err := clientParams.FromBytes(actualPayload); err != nil {
				dbg("Server: Malformed SYN parameters from %s: %v", remoteAddr, err)
				x.Close() // Refuse connection
				return
			}
			x.negotiateParameters(&clientParams) // Negotiate and store
			x.state = StateHandshake
			x.sendConnResponse()
			x.ulpSignaler.OnConnectionOpen(x.connID, remoteAddr) // Signal ULP
			dbg("Server received SYN from %s, sent SYN-ACK. Transitioned to Handshake state. Negotiated params: %+v", remoteAddr, x.negotiatedParams)
		} else if x.isServer && x.state == StateEstablished && (header.flags&FLAG_SYN) != 0 {
			// Auto Reset triggered by SYN (RUDP spec)
			dbg("Server received SYN from %s while established. Initiating auto reset.", remoteAddr)
			x.error.Store(ERROR_CONNECTION_BROKEN) // Trigger auto reset
			// The Update loop will pick this up and call performAutoReset
		}
	case TYPE_CONN_RSP: // Server SYN-ACK
		if !x.isServer && x.state == StateHandshake {
			var serverParams SYNParameters
			if err := serverParams.FromBytes(actualPayload); err != nil {
				dbg("Client: Malformed SYN-ACK parameters from %s: %v", remoteAddr, err)
				x.Close() // Refuse connection
				return
			}
			// Client accepts server's proposed parameters
			x.negotiatedParams = &serverParams
			x.sendConnConfirm()
			x.state = StateEstablished
			x.handshakeDone = true
			x.SetConnected(true) // Client: Handshake complete, set connected
			x.ulpSignaler.OnConnectionOpen(x.connID, remoteAddr) // Signal ULP
			dbg("Client received SYN-ACK, sent ACK, handshake complete. Transitioned to Established state. Negotiated params: %+v", x.negotiatedParams)
		}
	case TYPE_CONN_CFM: // Client ACK for handshake
		if x.isServer && x.state == StateHandshake {
			x.state = StateEstablished
			x.handshakeDone = true
			x.SetConnected(true) // Server: Handshake complete, set connected
			x.ulpSignaler.OnConnectionOpen(x.connID, remoteAddr) // Signal ULP
			dbg("Server received client ACK, handshake complete. Transitioned to Established state.")
			x.autoResetCount = 0 // Clear auto reset counter on successful connection
		}
	case TYPE_PING:
		dbg("Received PING from %s, packet ID %d.", remoteAddr, header.packetID)
		// ACK is already handled by addSendAck
	case TYPE_EOF:
		dbg("Received EOF from %s, packet ID %d. Setting connection error.", remoteAddr, header.packetID)
		x.error.Store(ERROR_REMOTE_EOF)
		x.Close()
	case TYPE_CORRUPT:
		dbg("Received CORRUPT notification from %s, packet ID %d. Setting connection error.", remoteAddr, header.packetID)
		x.error.Store(ERROR_CORRUPT)
		x.Close()
	case TYPE_RST:
		dbg("Received RST from %s, packet ID %d. Closing connection.", remoteAddr, header.packetID)
		x.error.Store(ERROR_REMOTE_EOF) // Treat RST as immediate EOF
		x.Close()

	case TYPE_REQUEST: // Request for missing packets (retransmission request)
		// Payload: [min_id (4 bytes)][max_id (4 bytes)]...
		if len(actualPayload)%8 != 0 {
			dbg("Malformed REQUEST payload from %s, packet ID %d.", remoteAddr, header.packetID)
			return
		}
		for i := 0; i < len(actualPayload); i += 8 {
			min := binary.BigEndian.Uint32(actualPayload[i : i+4])
			max := binary.BigEndian.Uint32(actualPayload[i+4 : i+8])
			stream := x.GetStream(header.streamID) // If streamID is 0, this gets default stream
			if stream != nil {
				select {
				case stream.addSendAgain <- EACKRange{Start: min, End: max}:
					dbg("Queued retransmission for stream %d, range %d-%d (requested by peer).", stream.ID, min, max)
				default:
					dbg("Stream %d addSendAgain channel full, dropping request for %d-%d.", stream.ID, min, max)
				}
			}
		}
	case TYPE_MISSING: // Notification of missing packets (informational)
		// Payload: [min_id (4 bytes)][max_id (4 bytes)]...
		if len(actualPayload)%8 != 0 {
			dbg("Malformed MISSING payload from %s, packet ID %d.", remoteAddr, header.packetID)
			return
		}
		for i := 0; i < len(actualPayload); i += 8 {
			min := binary.BigEndian.Uint32(actualPayload[i : i+4])
			max := binary.BigEndian.Uint32(actualPayload[i+4 : i+8])
			dbg("Received MISSING notification for range %d-%d from %s.", min, max, remoteAddr)
			// This information can be used for congestion control, but not directly for retransmission.
		}

	case TYPE_STREAM_FIN:
		stream := x.GetStream(header.streamID)
		if stream != nil {
			stream.Lock()
			if stream.State < StreamStateHalfClosedRemote {
				stream.State = StreamStateHalfClosedRemote
				dbg("Stream %d: Remote side sent FIN. State: Half-Closed (Remote).", stream.ID)
			} else if stream.State == StreamStateHalfClosedLocal {
				stream.State = StreamStateClosing
				dbg("Stream %d: Both sides sent FIN. State: Closing.", stream.ID)
			}
			stream.Unlock()
		}
	case TYPE_STREAM_RESET:
		stream := x.GetStream(header.streamID)
		if stream != nil {
			stream.Lock()
			stream.State = StreamStateReset
			stream.error.Store(ERROR_REMOTE_EOF) // Mark stream as reset
			dbg("Stream %d: Remote side sent RESET. State: Reset.", stream.ID)
			// Clear any pending data in send/recv queues for this stream
			stream.sendQueue.head = nil; stream.sendQueue.tail = nil; stream.sendQueue.num = 0
			stream.recvQueue.head = nil; stream.recvQueue.tail = nil; stream.recvQueue.num = 0
			stream.sendHistory.head = nil; stream.sendHistory.tail = nil; stream.sendHistory.num = 0
			stream.recvMissing.head = nil; stream.recvMissing.tail = nil; stream.recvMissing.num = 0
			stream.Unlock()
		}

	case TYPE_MAX_STREAM_DATA:
		if len(actualPayload) < 8 {
			dbg("Malformed MAX_STREAM_DATA control segment from %s.", remoteAddr)
			return
		}
		streamID := binary.BigEndian.Uint32(actualPayload[:4])
		maxOffset := binary.BigEndian.Uint32(actualPayload[4:8])
		stream := x.GetStream(streamID)
		if stream != nil {
			stream.Lock()
			stream.sendFlowWindow = maxOffset
			stream.Unlock()
			dbg("Stream %d: Updated send flow window to %d via control segment.", streamID, maxOffset)
		}
	case TYPE_MAX_CONNECTION_DATA:
		if len(actualPayload) < 4 {
			dbg("Malformed MAX_CONNECTION_DATA control segment from %s.", remoteAddr)
			return
		}
		maxOffset := binary.BigEndian.Uint32(actualPayload[:4])
		x.Lock()
		x.connSendFlowWindow = maxOffset
		x.Unlock()
		dbg("Connection: Updated send flow window to %d", maxOffset)

	case TYPE_PATH_CHALLENGE:
		if len(actualPayload) < 8 {
			dbg("Malformed PATH_CHALLENGE payload from %s.", remoteAddr)
			return
		}
		challenge := binary.BigEndian.Uint64(actualPayload[:8])
		dbg("Received PATH_CHALLENGE: %d from %s. Sending PATH_RESPONSE.", challenge, remoteAddr)
		x.queueControlSegment(TYPE_PATH_RESPONSE, binary.BigEndian.AppendUint64(nil, challenge), (x.negotiatedParams.OptionFlags&OPT_CHK_BIT) != 0)

	case TYPE_PATH_RESPONSE:
		if len(actualPayload) < 8 {
			dbg("Malformed PATH_RESPONSE payload from %s.", remoteAddr)
			return
		}
		response := binary.BigEndian.Uint64(actualPayload[:8])
		if pc, ok := x.pathChallengesSent[response]; ok {
			delete(x.pathChallengesSent, response)
			x.pathValidated = true
			x.currentRemoteAddr = remoteAddr
			dbg("Path validation successful for challenge: %d from %s. Switched sending path.", response, remoteAddr)
			pc.Retries = 0 // Reset retries on successful validation
		} else {
			dbg("Received unsolicited or invalid PATH_RESPONSE: %d from %s.", response, remoteAddr)
		}
	case TYPE_TCS: // Handle Transfer Connection State segment
		if len(actualPayload) < 8 { // Seq Adj Factor (4) + Connection Identifier (4)
			dbg("Malformed TCS payload from %s.", remoteAddr)
			return
		}
		seqAdjFactor := binary.BigEndian.Uint32(actualPayload[:4])
		receivedConnID := binary.BigEndian.Uint32(actualPayload[4:8]) // 32-bit CID in TCS spec

		dbg("Received TCS from %s. Seq Adj Factor: %d, Received Conn ID: %d", remoteAddr, seqAdjFactor, receivedConnID)

		// This is a simplified handling of TCS. In a full implementation:
		// 1. Verify `receivedConnID` matches a previously saved connection ID.
		// 2. Adjust all active stream sequence numbers (sendOffset, recvOffset) using `seqAdjFactor`.
		// 3. Potentially transfer state from a "broken" connection record to this one.
		// 4. Reset connection parameters as if it were a new connection, but using transferred state.
		// For now, we'll just log and acknowledge.
		// If we are currently in a broken state and this TCS is for our old CID,
		// we might transition to a new connection state.
		if x.error.Load() == ERROR_CONNECTION_BROKEN && x.connID == uint64(receivedConnID) {
			dbg("TCS received for broken connection %d. Initiating auto reset based on TCS.", x.connID)
			x.performAutoReset(&packageBuffer{}) // Trigger auto reset
		}
	default:
		dbg("Unknown control segment type: %x from %s, packet ID %d.", controlType, remoteAddr, header.packetID)
	}
}

// addSendAck adds an ACK to the list of ACKs to be sent in the next Update cycle.
func (x *XRUDP) addSendAck(id uint32) {
	x.sendAck[id] = struct{}{}
	// Reset cumulative ACK timer if it's running
	if x.conf.CumulativeAckTimeoutValue > 0 {
		x.cumulativeAckTimer.Reset(x.conf.CumulativeAckTimeoutValue)
	}
	x.cumulativeAckCount = 0 // Reset counter as we're about to send an ACK
}

// queueControlSegment queues a control segment to be sent in the next outgoing packet.
func (x *XRUDP) queueControlSegment(controlType byte, payload []byte, enableChecksum bool) { // 错误修复：添加 enableChecksum 参数
	segment := append([]byte{controlType}, payload...)
	select {
	case x.queueControl <- segment:
		dbg("Queued control segment: Type %x, Payload Len %d", controlType, len(payload))
	default:
		dbg("Control queue full, dropping control segment Type %x.", controlType)
	}
}

// queueFlowControlUpdate checks if flow control windows need to be updated and queues messages.
func (x *XRUDP) queueFlowControlUpdate() {
	// Connection-level window update
	// If enough data has been consumed to open up a significant portion of the window,
	// send a MAX_CONNECTION_DATA frame.
	x.Lock()
	currentConnRecvOffset := x.connRecvFlowWindow // Placeholder for actual consumed bytes
	// This logic needs to be more robust, based on actual consumption and available buffer space.
	// For simplicity, we'll use a threshold based on initial window.
	if currentConnRecvOffset+x.conf.InitialConnFlowWindow/2 > x.connRecvFlowWindow { // If half window consumed
		newMaxOffset := currentConnRecvOffset + x.conf.InitialConnFlowWindow
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, newMaxOffset)
		x.queueControlSegment(TYPE_MAX_CONNECTION_DATA, payload, (x.negotiatedParams.OptionFlags&OPT_CHK_BIT) != 0) // 错误修复：添加 enableChecksum 参数
		x.connRecvFlowWindow = newMaxOffset // Update our advertised window
		dbg("Queued MAX_CONNECTION_DATA with new max offset %d.", newMaxOffset)
	}
	x.Unlock()

	// Stream-level window updates
	for _, s := range x.streams {
		s.Lock()
		currentStreamRecvOffset := s.recvOffset // Placeholder for actual consumed bytes
		if currentStreamRecvOffset+x.conf.InitialStreamFlowWindow/2 > s.recvFlowWindow {
			newMaxOffset := currentStreamRecvOffset + x.conf.InitialStreamFlowWindow
			payload := make([]byte, 8) // StreamID (4) + MaxOffset (4)
			binary.BigEndian.PutUint32(payload[:4], s.ID)
			binary.BigEndian.PutUint32(payload[4:8], newMaxOffset)
			x.queueControlSegment(TYPE_MAX_STREAM_DATA, payload, (x.negotiatedParams.OptionFlags&OPT_CHK_BIT) != 0) // 错误修复：添加 enableChecksum 参数
			s.recvFlowWindow = newMaxOffset
			dbg("Queued MAX_STREAM_DATA for stream %d with new max offset %d.", s.ID, newMaxOffset)
		}
		s.Unlock()
	}
}

// sendRST sends a RST control segment to the peer.
func (x *XRUDP) sendRST() {
	enableChecksum := false
	if x.negotiatedParams != nil {
		enableChecksum = (x.negotiatedParams.OptionFlags & OPT_CHK_BIT) != 0
	} else {
		enableChecksum = (x.conf.OptionFlags & OPT_CHK_BIT) != 0
	}
	x.queueControlSegment(TYPE_RST, nil, enableChecksum)
	dbg("Queued RST segment for connection %d.", x.connID)
}

// sendConnRequest sends a connection request (SYN) packet.
func (x *XRUDP) sendConnRequest() {
	x.sendPacketNum++
	// Populate SYN parameters from config
	synParams := &SYNParameters{
		Version:                  x.conf.Version,
		MaxOutstandingSegs:       x.conf.MaxOutstandingSegs,
		OptionFlags:              x.conf.OptionFlags,
		MaxSegmentSize:           x.conf.MaxSegmentSize,
		RetransmissionTimeoutValue: uint16(x.conf.RetransmissionTimeoutValue / time.Millisecond), // 错误修复：将 time.Duration 转换为 uint16
		CumulativeAckTimeoutValue: uint16(x.conf.CumulativeAckTimeoutValue / time.Millisecond), // 错误修复：将 time.Duration 转换为 uint16
		NullSegmentTimeoutValue:    uint16(x.conf.NullSegmentTimeoutValue / time.Millisecond),    // 错误修复：将 time.Duration 转换为 uint16
		TransferStateTimeoutValue:  uint16(x.conf.TransferStateTimeoutValue / time.Millisecond),  // 错误修复：将 time.Duration 转换为 uint16
		MaxRetrans:                 x.conf.MaxRetrans,
		MaxCumAck:                  x.conf.MaxCumAck,
		MaxOutOfSeq:                x.conf.MaxOutOfSeq,
		MaxAutoReset:               x.conf.MaxAutoReset,
		ConnectionIdentifier:       uint32(x.connID), // Use our current CID for SYN
	}
	payload := synParams.ToBytes()

	header := &packetHeader{
		connID: 0, // Client initially sends with CID 0 in header, but includes its CID in payload
		packetID: x.sendPacketNum,
		packetType: TYPE_CONN_REQ,
		flags: FLAG_SYN, // Indicate SYN packet
	}
	// Checksum bit based on config
	enableChecksum := (x.conf.OptionFlags & OPT_CHK_BIT) != 0
	x.packControlSegment(&packageBuffer{}, TYPE_CONN_REQ, header.packetID, payload, enableChecksum)
	dbg("Client: prepared SYN packet with ID %d, payload params: %+v", header.packetID, synParams)
}

// sendConnResponse sends a connection response (SYN-ACK) packet.
func (x *XRUDP) sendConnResponse() {
	x.sendPacketNum++
	// Populate SYN-ACK parameters (negotiated values)
	synParams := &SYNParameters{
		Version:                  x.negotiatedParams.Version,
		MaxOutstandingSegs:       x.negotiatedParams.MaxOutstandingSegs,
		OptionFlags:              x.negotiatedParams.OptionFlags,
		MaxSegmentSize:           x.negotiatedParams.MaxSegmentSize,
                CumulativeAckTimeoutValue:  uint16(time.Duration(x.negotiatedParams.CumulativeAckTimeoutValue) / time.Millisecond),
                NullSegmentTimeoutValue:    uint16(time.Duration(x.negotiatedParams.NullSegmentTimeoutValue) / time.Millisecond),
                TransferStateTimeoutValue:  uint16(time.Duration(x.negotiatedParams.TransferStateTimeoutValue) / time.Millisecond),
		RetransmissionTimeoutValue: uint16(time.Duration(x.negotiatedParams.RetransmissionTimeoutValue) / time.Millisecond),
		MaxRetrans:                 x.negotiatedParams.MaxRetrans,
		MaxCumAck:                  x.negotiatedParams.MaxCumAck,
		MaxOutOfSeq:                x.negotiatedParams.MaxOutOfSeq,
		MaxAutoReset:               x.negotiatedParams.MaxAutoReset,
		ConnectionIdentifier:       uint32(x.connID), // Server sends its assigned CID
	}
	payload := synParams.ToBytes()

	header := &packetHeader{
		connID: x.connID, // Server sends its assigned CID
		packetID: x.sendPacketNum,
		packetType: TYPE_CONN_RSP,
		flags: FLAG_SYN | FLAG_ACK, // Indicate SYN-ACK
	}
	// Checksum bit based on negotiated parameters
	enableChecksum := (x.negotiatedParams.OptionFlags & OPT_CHK_BIT) != 0
	x.packControlSegment(&packageBuffer{}, TYPE_CONN_RSP, header.packetID, payload, enableChecksum)
	dbg("Server: prepared SYN-ACK packet with ID %d, CID %d, payload params: %+v", header.packetID, x.connID, synParams)
}

// sendConnConfirm sends a connection confirm (ACK) packet.
func (x *XRUDP) sendConnConfirm() {
	x.sendPacketNum++
	header := &packetHeader{
		connID: x.connID, // Client sends the server's assigned CID
		packetID: x.sendPacketNum,
		packetType: TYPE_CONN_CFM,
		flags: FLAG_ACK_ONLY, // Pure ACK packet
	}
	// Checksum bit based on negotiated parameters
	enableChecksum := (x.negotiatedParams.OptionFlags & OPT_CHK_BIT) != 0
	x.packControlSegment(&packageBuffer{}, TYPE_CONN_CFM, header.packetID, nil, enableChecksum)
	dbg("Client: prepared ACK (confirm) packet with ID %d, CID %d", x.connID, header.packetID)
}

// sendTCS sends a Transfer Connection State (TCS) segment.
func (x *XRUDP) sendTCS(seqAdjFactor uint32, oldConnID uint32) {
	payload := make([]byte, 8) // Seq Adj Factor (4) + Connection Identifier (4)
	binary.BigEndian.PutUint32(payload[:4], seqAdjFactor)
	binary.BigEndian.PutUint32(payload[4:8], oldConnID) // The old CID being transferred from

	x.sendPacketNum++
	header := &packetHeader{
		connID: x.connID,
		packetID: x.sendPacketNum,
		packetType: TYPE_TCS,
		flags: FLAG_TCS | FLAG_ACK, // TCS always includes ACK
	}
	enableChecksum := false
	if x.negotiatedParams != nil {
		enableChecksum = (x.negotiatedParams.OptionFlags & OPT_CHK_BIT) != 0
	} else {
		enableChecksum = (x.conf.OptionFlags & OPT_CHK_BIT) != 0
	}
	x.packControlSegment(&packageBuffer{}, TYPE_TCS, header.packetID, payload, enableChecksum)
	dbg("Queued TCS segment for connection %d. Seq Adj Factor: %d, Old CID: %d", x.connID, seqAdjFactor, oldConnID)
}


// initiatePathValidation sends a PATH_CHALLENGE to a new remote address.
func (x *XRUDP) initiatePathValidation(newRemoteAddr *net.UDPAddr) {
	// Check if a challenge is already outstanding for this path
	for _, pc := range x.pathChallengesSent {
		if time.Since(pc.SentTime) < x.conf.PathChallengeTimeout && pc.Retries < x.conf.MaxPathChallengeRetries {
			dbg("Path validation already in progress for %s. Retries: %d", newRemoteAddr.String(), pc.Retries)
			return
		}
	}

	challenge := generateConnectionID() // Re-using CID generator for random number
	x.pathChallengesSent[challenge] = &PathChallenge{
		Challenge: challenge,
		SentTime:  time.Now(),
		Retries:   1,
	}

	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, challenge)
	enableChecksum := false
	if x.negotiatedParams != nil {
		enableChecksum = (x.negotiatedParams.OptionFlags & OPT_CHK_BIT) != 0
	} else {
		enableChecksum = (x.conf.OptionFlags & OPT_CHK_BIT) != 0
	}
	x.queueControlSegment(TYPE_PATH_CHALLENGE, payload, enableChecksum)
	dbg("Initiated path validation for %s with challenge %d", newRemoteAddr.String(), challenge)
}

// addSessionTicket adds a 0-RTT session ticket to the cache.
func (x *XRUDP) addSessionTicket(ticket *SessionTicket) {
	if len(x.sessionTickets) >= x.conf.MaxZeroRTTSessionTickets {
		x.sessionTickets = x.sessionTickets[1:] // Remove oldest
	}
	x.sessionTickets = append(x.sessionTickets, ticket)
	dbg("Added 0-RTT session ticket. Total: %d", len(x.sessionTickets))
}

// parseSessionTicket parses and decrypts a session ticket.
func (x *XRUDP) parseSessionTicket(ticketValue []byte) (*SessionTicket, error) {
	// 错误修复：添加 DecryptSessionTicket 函数的定义，或者确保它在其他文件中可用
	// 假设这里有一个简单的模拟实现，因为它在原始代码中没有提供
	// 如果您有实际的加密套件，请替换此模拟
	//
	// 这是一个模拟函数，实际的 DecryptSessionTicket 会进行解密
	// 注意：这里直接使用函数名，而不是作为局部变量，以避免冲突
	// 如果 DecryptSessionTicket 已经在 xrudp_crypto.go 中定义，则无需再次定义
	// 为了避免重复定义，这里将其注释掉，假设它在 xrudp_crypto.go 中已正确定义并导入
	/*
	DecryptSessionTicket := func(data []byte) ([]byte, error) {
		if len(data) < 8 { // 假设至少需要8字节来提取 nonce
			return nil, errors.New("ticket data too short for decryption")
		}
		// 模拟解密：直接返回数据，或者进行简单的异或操作
		decrypted := make([]byte, len(data))
		for i, b := range data {
			decrypted[i] = b ^ 0xAA // 简单的模拟解密
		}
		return decrypted, nil
	}
	*/

	decrypted, err := DecryptSessionTicket(ticketValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session ticket: %w", err)
	}
	if len(decrypted) < 8 { // Assuming first 8 bytes is nonce
		return nil, errors.New("decrypted ticket too short for nonce")
	}
	nonce := binary.BigEndian.Uint64(decrypted[:8])
	// In a real implementation, parse other parameters from `decrypted`
	return &SessionTicket{
		Ticket:    ticketValue, // Store original encrypted ticket
		IssueTime: time.Now(),  // Placeholder, should be from ticket content
		Nonce:     nonce,
	}, nil
}

// process0RTTSessionTicket processes an incoming 0-RTT session ticket from a client.
func (x *XRUDP) process0RTTSessionTicket(ticketValue []byte, remoteAddr *net.UDPAddr) {
	ticket, err := x.parseSessionTicket(ticketValue)
	if err != nil {
		dbg("Failed to parse/decrypt 0-RTT ticket from %s: %v", remoteAddr, err)
		x.error.Store(ERROR_0RTT_REPLAY) // Treat as replay/invalid
		return
	}

	// Replay protection
	if lastUseTime, ok := x.replayNonces[ticket.Nonce]; ok {
		if time.Since(lastUseTime) < x.conf.ZeroRTTReplayWindow {
			dbg("0-RTT replay detected for nonce %d from %s. Dropping.", ticket.Nonce, remoteAddr)
			x.error.Store(ERROR_0RTT_REPLAY)
			return
		}
	}
	x.replayNonces[ticket.Nonce] = time.Now()
	dbg("Processed 0-RTT ticket with nonce %d from %s. Replay protection updated.", ticket.Nonce, remoteAddr)

	// If valid, apply session parameters and allow 0-RTT data.
	// For prototype, assume valid and transition to established.
	x.state = StateEstablished
	x.handshakeDone = true
	x.SetConnected(true) // 0-RTT handshake complete, set connected
	dbg("0-RTT session ticket processed successfully from %s. Connection %d established.", remoteAddr, x.connID)
	x.ulpSignaler.OnConnectionOpen(x.connID, remoteAddr) // Signal ULP
}

// SetConfig sets the configuration for the XRUDP instance.
func (x *XRUDP) SetConfig(conf *XRUDPConfig) {
	x.conf = conf
}

// GetConf gets the current configuration.
func (x *XRUDP) GetConf() *XRUDPConfig {
	return x.conf
}

// Connected 返回 XRUDP 连接是否处于连接状态。
// 这通常用于判断是否可以发送应用数据，或者连接是否已通过握手。
func (r *XRUDP) Connected() bool {
    return atomic.LoadInt32(&r.connected) == 1
}

// SetConnected 设置 XRUDP 连接的连接状态。
// 这在握手成功或连接关闭时调用。
func (r *XRUDP) SetConnected(status bool) {
    if status {
        atomic.StoreInt32(&r.connected, 1)
    } else {
        atomic.StoreInt32(&r.connected, 0)
    }
    dbg("XRUDP connection %d connected status set to %t", r.connID, status)
}

// RemoteAddr returns the remote address of the connection.
func (x *XRUDP) RemoteAddr() net.Addr {
	if x.currentRemoteAddr != nil {
		return x.currentRemoteAddr
	}
	return x.remoteAddr
}

// negotiateParameters negotiates SYN parameters between client and server.
// This is called by the server when it receives a client's SYN.
func (x *XRUDP) negotiateParameters(clientParams *SYNParameters) {
	// Start with server's desired parameters
	negotiated := &SYNParameters{
		Version:                  x.conf.Version,
		MaxOutstandingSegs:       x.conf.MaxOutstandingSegs,
		OptionFlags:              x.conf.OptionFlags,
		MaxSegmentSize:           x.conf.MaxSegmentSize,
		RetransmissionTimeoutValue: x.negotiatedParams.RetransmissionTimeoutValue,
		CumulativeAckTimeoutValue: x.negotiatedParams.CumulativeAckTimeoutValue,
		NullSegmentTimeoutValue:    x.negotiatedParams.NullSegmentTimeoutValue,
		TransferStateTimeoutValue:  x.negotiatedParams.TransferStateTimeoutValue,
		MaxRetrans:                 x.conf.MaxRetrans,
		MaxCumAck:                  x.conf.MaxCumAck,
		MaxOutOfSeq:                x.conf.MaxOutOfSeq,
		MaxAutoReset:               x.conf.MaxAutoReset,
		ConnectionIdentifier:       uint32(x.connID), // Server's own CID
	}

	// Negotiate each parameter. Typically, the minimum or a mutually agreeable value.
	// For simplicity, we'll pick the server's value if it's within client's range,
	// or the client's value if server's is too high.
	// Or, as per RUDP spec, "each side must use the value provided by its peer when sending data"
	// for Max # of Outstanding Segments and Max Segment Size.
	// For negotiable parameters, "both peers must agree on the same value".
	// Here, server proposes its values, and client accepts or rejects.

	// Version: Server's version
	if clientParams.Version != negotiated.Version {
		dbg("Warning: Client proposed RUDP version %d, server uses %d. Using server's version.", clientParams.Version, negotiated.Version)
	}

	// Max # of Outstanding Segments: Each side uses peer's value. Server echoes its own.
	// This is NOT a negotiable parameter, so server just sets its own.
	// Client will use the value received from server.

	// Option Flags: Negotiable. Server proposes its flags.
	// If CHK bit is set by client, server can accept it.
	if (clientParams.OptionFlags & OPT_CHK_BIT) != 0 {
		negotiated.OptionFlags |= OPT_CHK_BIT // Server accepts CHK if client wants it
	}
	// REUSE bit is handled during auto reset.

	// Max Segment Size: Each side uses peer's value. Server echoes its own.
	// This is NOT a negotiable parameter.

	// Retransmission Timeout Value: Negotiable. Both must agree. Server proposes its value.
	// If client's proposed is lower, server might accept it or reject.
	// For simplicity, server proposes its value. Client will accept or RST.
	
	// Apply negotiated parameters to XRUDP instance's config
	x.conf.Version = negotiated.Version
	x.conf.MaxOutstandingSegs = negotiated.MaxOutstandingSegs
	x.conf.OptionFlags = negotiated.OptionFlags
	x.conf.MaxSegmentSize = negotiated.MaxSegmentSize
	x.conf.RetransmissionTimeoutValue = time.Duration(negotiated.RetransmissionTimeoutValue) * time.Millisecond
	x.conf.CumulativeAckTimeoutValue = time.Duration(negotiated.CumulativeAckTimeoutValue) * time.Millisecond
	x.conf.NullSegmentTimeoutValue = time.Duration(negotiated.NullSegmentTimeoutValue) * time.Millisecond
	x.conf.TransferStateTimeoutValue = time.Duration(negotiated.TransferStateTimeoutValue) * time.Millisecond
	x.conf.MaxRetrans = negotiated.MaxRetrans
	x.conf.MaxCumAck = negotiated.MaxCumAck
	x.conf.MaxOutOfSeq = negotiated.MaxOutOfSeq
	x.conf.MaxAutoReset = negotiated.MaxAutoReset

	x.negotiatedParams = negotiated // Store the negotiated parameters
}
