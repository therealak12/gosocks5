package gosocks5

import (
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"net"
	"strconv"
)

type SocksAddr struct {
	addrType AddrType
	ip       net.IP
	name     string
	port     uint16
}

func (sa *SocksAddr) Network() string { return "socks5" }

func (sa *SocksAddr) String() string {
	if sa == nil {
		return "<nil>"
	}
	return sa.Address()
}

func (sa *SocksAddr) Address() string {
	port := strconv.FormatUint(uint64(sa.port), 10)
	if 0 != len(sa.ip) {
		return net.JoinHostPort(sa.ip.String(), port)
	}
	return net.JoinHostPort(sa.name, port)
}

func getNetAddr(network string, ip net.IP, port int) (net.Addr, error) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	switch network {
	case "tcp":
		return net.ResolveTCPAddr(network, addr)
	case "udp":
		return net.ResolveUDPAddr(network, addr)
	default:
		return nil, fmt.Errorf("unsupported network %s", network)
	}
}

func getAddrLen(addrType AddrType) (uint8, error) {
	switch addrType {
	case addrTypeIPv4:
		return addrLenIPv4, nil
	case addrTypeFQDN:
		return addrLenFQDN, nil
	case addrTypeIPv6:
		return addrLenIPv6, nil
	}
	return 0, fmt.Errorf("unsupported address type %d", addrType)
}

func resolveAddr(addr string) (net.IP, error) {
	ip := net.ParseIP(addr)
	if ip != nil {
		return ip, nil
	}

	ipAddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return nil, err
	}

	return ipAddr.IP, nil
}

func readAddrPort(r io.Reader) (*SocksAddr, error) {
	socksAddr := &SocksAddr{}

	addrTypeBuf := make([]byte, 1)
	_, err := io.ReadFull(r, addrTypeBuf)
	if err != nil {
		return nil, err
	}

	var dstAddrBuf []byte
	switch AddrType(addrTypeBuf[0]) {
	case addrTypeIPv4:
		dstAddrBuf = make([]byte, addrLenIPv4)
		_, err = io.ReadFull(r, dstAddrBuf)
		if err != nil {
			return nil, err
		}
		socksAddr.ip = dstAddrBuf
	case addrTypeFQDN:
		addressLenBuf := make([]byte, addrLenFQDN)
		_, err = io.ReadFull(r, addressLenBuf)
		if err != nil {
			return nil, err
		}

		dstAddrBuf = make([]byte, int(addressLenBuf[0]))
		_, err = io.ReadFull(r, dstAddrBuf)
		if err != nil {
			return nil, err
		}
		socksAddr.name = string(dstAddrBuf)
	case addrTypeIPv6:
		dstAddrBuf = make([]byte, addrLenIPv6)
		_, err = io.ReadFull(r, dstAddrBuf)
		if err != nil {
			return nil, err
		}
		socksAddr.ip = dstAddrBuf
	default:
		return nil, ErrInvalidAddrType
	}

	socksAddr.addrType = AddrType(addrTypeBuf[0])

	portBuf := make([]byte, 2)
	_, err = io.ReadFull(r, portBuf)
	if err != nil {
		return nil, err
	}

	socksAddr.port = binary.BigEndian.Uint16(portBuf)

	return socksAddr, nil
}

func writeAddrPort(w io.Writer, addr string, resolve bool) error {
	socksAddr, err := parseAddr(addr, resolve)
	if err != nil {
		return err
	}

	reqBytes := make([]byte, 0)

	if socksAddr.name == "" && socksAddr.ip == nil {
		_, err := w.Write([]byte{byte(addrTypeIPv4), 0, 0, 0, 0, 0, 0})
		return err
	}

	reqBytes = append(reqBytes, byte(socksAddr.addrType))

	switch socksAddr.addrType {
	case addrTypeFQDN:
		reqBytes = append(reqBytes, byte(len(socksAddr.name)))
		reqBytes = append(reqBytes, []byte(socksAddr.name)...)
	case addrTypeIPv4:
		reqBytes = append(reqBytes, socksAddr.ip.To4()...)
	case addrTypeIPv6:
		reqBytes = append(reqBytes, socksAddr.ip.To16()...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, socksAddr.port)
	reqBytes = append(reqBytes, portBytes...)

	_, err = w.Write(reqBytes)
	return err
}

func parseAddr(addr string, resolve bool) (*SocksAddr, error) {
	socksAddr := &SocksAddr{}

	// We expect The caller to have parsed the address.
	// it should be in `host:port` format.
	addr, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to split host,port")
	}

	if resolve {
		ip, err := resolveAddr(addr)
		if err != nil {
			return nil, errors.Wrap(err, "failed to resolve addr")
		}
		if ip != nil {
			addr = ip.String()
		}
	}

	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse port to uint")
	}
	socksAddr.port = uint16(value)

	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() != nil {
			socksAddr.addrType = addrTypeIPv4
			socksAddr.ip = ip.To4()
		} else if ip.To16() != nil {
			socksAddr.addrType = addrTypeIPv6
			socksAddr.ip = ip.To16()
		}
		socksAddr.ip = ip
	} else {
		socksAddr.addrType = addrTypeFQDN
		socksAddr.name = addr
	}

	return socksAddr, nil
}
