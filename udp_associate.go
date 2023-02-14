package gosocks5

import (
	"bytes"
	"fmt"
	"net"
)

type UDPAssociateConn struct {
	net.PacketConn
	headerPrefix  []byte
	proxyAddr     *net.UDPAddr
	defaultTarget net.Addr
	readingBuf    []byte
}

func NewUDPAssociateConn(packetConn net.PacketConn, proxyAddr *SocksAddr, defaultTarget *net.UDPAddr) (*UDPAssociateConn, error) {
	headerPrefix := []byte{0, 0, 0}

	var (
		proxyIP net.IP
		err     error
	)
	switch proxyAddr.addrType {
	case addrTypeIPv4, addrTypeIPv6:
		proxyIP = proxyAddr.ip
	case addrTypeFQDN:
		proxyIP, err = resolveAddr(proxyAddr.name)
		if err != nil {
			return nil, err
		}
	}

	proxyUDPAddr := &net.UDPAddr{
		IP:   proxyIP,
		Port: int(proxyAddr.port),
	}

	return &UDPAssociateConn{
		PacketConn:    packetConn,
		proxyAddr:     proxyUDPAddr,
		headerPrefix:  headerPrefix,
		defaultTarget: defaultTarget,
		readingBuf:    make([]byte, maxUDPPacketSize),
	}, nil
}

func (uac *UDPAssociateConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = uac.PacketConn.ReadFrom(uac.readingBuf[:])
	if err != nil {
		return 0, nil, err
	}

	if n < len(uac.headerPrefix) {
		return 0, nil, fmt.Errorf("too short response length %d", n)
	}
	if addr.String() != uac.proxyAddr.String() {
		return 0, nil, fmt.Errorf("addr %s doesn't match proxyAddr", addr.String())
	}

	buf := bytes.NewBuffer(uac.readingBuf[len(uac.headerPrefix):])
	socksAddr, err := readAddrPort(buf)
	if err != nil {
		return 0, nil, err
	}

	n = copy(p, buf.Bytes())

	return n, socksAddr, err
}

func (uac *UDPAssociateConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := bytes.NewBuffer(make([]byte, 0))

	if _, err = buf.Write(uac.headerPrefix); err != nil {
		return 0, err
	}
	if err := writeAddrPort(buf, addr.String(), false); err != nil {
		return 0, err
	}

	if n, err = buf.Write(p); err != nil {
		return 0, err
	}

	_, err = uac.PacketConn.WriteTo(buf.Bytes(), uac.proxyAddr)
	if err != nil {
		return 0, err
	}

	return n, err
}

func (uac *UDPAssociateConn) Read(b []byte) (int, error) {
	n, addr, err := uac.ReadFrom(b)
	if err != nil {
		return 0, err
	}
	// ignore the packet if it's not from the desired server
	// and wait for another packet
	if addr.String() != uac.defaultTarget.String() {
		return uac.Read(b)
	}
	return n, nil
}

func (uac *UDPAssociateConn) Write(b []byte) (int, error) {
	return uac.WriteTo(b, uac.defaultTarget)
}

func (uac *UDPAssociateConn) RemoteAddr() net.Addr {
	return uac.defaultTarget
}
