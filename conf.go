package xrudp

import "time"

// debug is a package-level variable that controls debug logging for the xrudp package.
// Functions like dbg() will directly check this variable.
var debug bool = false

// SetDebugFlag allows external callers to set the package-level debug flag.
// This is typically called once during application initialization based on overall config.
func SetDebugFlag(d bool) {
	debug = d
}

// XRUDPConfig holds all configurable parameters for an XRUDP instance.
// These parameters can be negotiated during connection establishment.
type XRUDPConfig struct {
	// General XRUDP parameters (from original conf.go)
	CorruptTick        time.Duration // How long before considering connection corrupt if no packets
	ExpiredTick        time.Duration // How long to keep packets in send history for retransmission
	SendDelayTick      time.Duration // Delay between sending packets (not actively used for rate control)
	MissingTime        time.Duration // How long to wait before requesting missing packets (EACK)

	// XRUDPConn parameters (from original conf.go)
	// The Debug field here serves as an initial configuration value for the package-level debug flag.
	Debug              bool          // Initial debug logging setting for this config instance
	AutoSend           bool          // Auto send packets (always true for continuous operation)
	SendTick           time.Duration // Interval for the main send loop ticker
	MaxSendNumPerTick  int           // Max number of packets to send per tick (not actively used for flow control)

	// Negotiable Parameters (from RUDP Spec Figure 2 and related sections)
	Version                  uint8         // RUDP Protocol Version (initial is 1)
	MaxOutstandingSegs       uint16        // Max segments peer can send without ACK (flow control)
	OptionFlags              uint16        // Various connection options (e.g., CHK, REUSE)
	MaxSegmentSize           uint16        // Max payload size peer can receive (including RUDP header)
	RetransmissionTimeoutValue time.Duration // RTO for unacknowledged packets
	CumulativeAckTimeoutValue time.Duration // Timeout for sending ACK if no other segments sent
	NullSegmentTimeoutValue    time.Duration // Timeout for sending NUL segment (keep-alive)
	TransferStateTimeoutValue  time.Duration // Timeout for state transfer after connection failure
	MaxRetrans                 uint8         // Max consecutive retransmissions before broken
	MaxCumAck                  uint8         // Max accumulated unacknowledged segments before sending ACK/EACK
	MaxOutOfSeq                uint8         // Max out-of-sequence packets before sending EACK
	MaxAutoReset               uint8         // Max consecutive auto resets before connection is truly reset

	// 0-RTT related
	MaxZeroRTTSessionTickets   int           // Max 0-RTT session tickets to cache
	ZeroRTTReplayWindow        time.Duration // Window for 0-RTT replay protection

	// Connection-level flow control (initial values)
	InitialConnFlowWindow uint32 // Initial connection-level flow control window size
	InitialStreamFlowWindow uint32 // Initial stream-level flow control window size

	// Path management
	PathChallengeTimeout       time.Duration // Timeout for path challenge response
	MaxPathChallengeRetries    int           // Max retries for path challenge
}

// OptionFlags bits
const (
	OPT_CHK_BIT    uint16 = 1 << 1 // Data Checksum enable
	OPT_REUSE_BIT  uint16 = 1 << 2 // Reuse previous negotiable parameters during auto reset
)

// NewDefaultConfig creates a default XRUDP configuration.
func NewDefaultConfig() *XRUDPConfig {
	return &XRUDPConfig{
		// Original defaults
		CorruptTick:        5 * time.Second,
		ExpiredTick:        5 * time.Minute, // 5 minutes on sendTick 10ms (5 * 60 * 100 = 30000 ticks)
		SendDelayTick:      10 * time.Millisecond,
		MissingTime:        100 * time.Millisecond, // How long to wait for missing
		Debug:              true, // Default to true for this config instance
		AutoSend:           true,
		SendTick:           10 * time.Millisecond, // Main loop tick interval
		MaxSendNumPerTick:  500,

		// RUDP Spec defaults / sensible values for negotiation
		Version:                  1,
		MaxOutstandingSegs:       32, // Recommended from spec (Receiver Input Queue Size)
		OptionFlags:              (1 << 0), // Bit 0 must always be 1 according to spec
		MaxSegmentSize:           1472, // Max UDP payload (1500 - IP - UDP headers)
		RetransmissionTimeoutValue: 600 * time.Millisecond, // Recommended from spec
		CumulativeAckTimeoutValue: 300 * time.Millisecond, // Recommended from spec
		NullSegmentTimeoutValue:    2 * time.Second,        // Recommended from spec
		TransferStateTimeoutValue:  1 * time.Second,        // Recommended from spec
		MaxRetrans:                 2,                      // Recommended from spec
		MaxCumAck:                  3,                      // Recommended from spec
		MaxOutOfSeq:                3,                      // Recommended from spec
		MaxAutoReset:               3,                      // Recommended from spec

		// 0-RTT related
		MaxZeroRTTSessionTickets: 16,
		ZeroRTTReplayWindow:      5 * time.Minute, // Example: 5 minutes replay window

		// Flow control
		InitialConnFlowWindow: 1024 * 1024, // 1MB initial connection window
		InitialStreamFlowWindow: 256 * 1024, // 256KB initial stream window

		// Path management
		PathChallengeTimeout:    5 * time.Second,
		MaxPathChallengeRetries: 3,
	}
}

// SetCorruptTick sets the corrupt tick duration.
func (c *XRUDPConfig) SetCorruptTick(tick time.Duration) { c.CorruptTick = tick }
// SetExpiredTick sets the expired tick duration.
func (c *XRUDPConfig) SetExpiredTick(tick time.Duration) { c.ExpiredTick = tick }
// SetSendDelayTick sets the send delay tick duration.
func (c *XRUDPConfig) SetSendDelayTick(tick time.Duration) { c.SendDelayTick = tick }
// SetMissingTime sets the missing time duration.
func (c *XRUDPConfig) SetMissingTime(miss time.Duration) { c.MissingTime = miss }

// SetAutoSend enables or disables auto sending.
func (c *XRUDPConfig) SetAutoSend(send bool) { c.AutoSend = send }
// SetSendTick sets the send tick duration.
func (c *XRUDPConfig) SetSendTick(tick time.Duration) { c.SendTick = tick }
// SetMaxSendNumPerTick sets the maximum number of packets to send per tick.
func (c *XRUDPConfig) SetMaxSendNumPerTick(n int) { c.MaxSendNumPerTick = n }

// SetMaxOutstandingSegs sets the maximum number of outstanding segments.
func (c *XRUDPConfig) SetMaxOutstandingSegs(n uint16) { c.MaxOutstandingSegs = n }
// SetMaxSegmentSize sets the maximum segment size.
func (c *XRUDPConfig) SetMaxSegmentSize(n uint16) { c.MaxSegmentSize = n }
// SetRetransmissionTimeoutValue sets the retransmission timeout value.
func (c *XRUDPConfig) SetRetransmissionTimeoutValue(d time.Duration) { c.RetransmissionTimeoutValue = d }
// SetCumulativeAckTimeoutValue sets the cumulative ACK timeout value.
func (c *XRUDPConfig) SetCumulativeAckTimeoutValue(d time.Duration) { c.CumulativeAckTimeoutValue = d }
// SetNullSegmentTimeoutValue sets the null segment timeout value.
func (c *XRUDPConfig) SetNullSegmentTimeoutValue(d time.Duration) { c.NullSegmentTimeoutValue = d }
// SetTransferStateTimeoutValue sets the transfer state timeout value.
func (c *XRUDPConfig) SetTransferStateTimeoutValue(d time.Duration) { c.TransferStateTimeoutValue = d }
// SetMaxRetrans sets the maximum number of retransmissions.
func (c *XRUDPConfig) SetMaxRetrans(n uint8) { c.MaxRetrans = n }
// SetMaxCumAck sets the maximum cumulative ACKs.
func (c *XRUDPConfig) SetMaxCumAck(n uint8) { c.MaxCumAck = n }
// SetMaxOutOfSeq sets the maximum out-of-sequence packets.
func (c *XRUDPConfig) SetMaxOutOfSeq(n uint8) { c.MaxOutOfSeq = n }
// SetMaxAutoReset sets the maximum auto resets.
func (c *XRUDPConfig) SetMaxAutoReset(n uint8) { c.MaxAutoReset = n }
// SetOptionFlags sets the option flags.
func (c *XRUDPConfig) SetOptionFlags(flags uint16) { c.OptionFlags = flags }
// EnableOptionFlag enables a specific option flag.
func (c *XRUDPConfig) EnableOptionFlag(flag uint16) { c.OptionFlags |= flag }
// DisableOptionFlag disables a specific option flag.
func (c *XRUDPConfig) DisableOptionFlag(flag uint16) { c.OptionFlags &^= flag }
// IsOptionFlagEnabled checks if a specific option flag is enabled.
func (c *XRUDPConfig) IsOptionFlagEnabled(flag uint16) bool { return (c.OptionFlags & flag) != 0 }
