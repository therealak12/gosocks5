package gosocks5

import "math"

type AddrType uint8

type Error string

func (e Error) Error() string {
	return string(e)
}

const (
	ErrInvalidAddrType = Error("invalid address type")
)

const (
	defaultPort   = 1080
	socks5Version = 5

	noAuthMethod          = 0
	noAcceptableMethod    = 0xff
	userPassMethod        = 2
	subnegotiationVersion = 1

	authStatusSuccess = 0
	// authStatusFailure can be anything other than 0
	authStatusFailure = 1

	requestReservedBytesCount = 1

	addrTypeIPv4 AddrType = 1
	addrTypeFQDN AddrType = 3
	addrTypeIPv6 AddrType = 4

	addrLenIPv4 = 4
	addrLenFQDN = 1
	addrLenIPv6 = 16

	cmdConnect      = 1
	cmdBind         = 2
	cmdUDPAssociate = 3

	replySucceeded                     = 0
	replyGeneralSOCKSServerFailure     = 1
	replyConnectionNotAllowedByRuleset = 2
	replyNetworkUnreachable            = 3
	replyHostUnreachable               = 4
	replyConnectionRefused             = 5
	replyTTLExpired                    = 6
	replyCommandNotSupported           = 7
	replyAddressTypeNotSupported       = 8

	maxUDPPacketSize   = math.MaxUint16 - 28
	udpAssociateNoFrag = 0

	// RSV + FRAG + ATYP + (at least 2 bytes for ADDR) + PORT
	minUDPAssociatePacketSize = 8
)
