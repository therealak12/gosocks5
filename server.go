package gosocks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"net"
	"strconv"
)

type Server struct {
	Host string
	Port int
}

type UDPAssociatePacket struct {
	AddrType AddrType
	DstIP    net.IP
	DstPort  uint16
	Data     []byte
}

func NewServer(host string, port int) *Server {
	if port == 0 {
		port = defaultPort
	}
	return &Server{
		Host: host,
		Port: port,
	}
}

// ListenAndServe listens on the configured tcp address and
// calls Serve to handle the incoming connections
func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port))
	if err != nil {
		return errors.Wrap(err, "failed to listen")
	}

	return s.serve(listener)
}

// Serve accepts new connections and creates a new goroutine
// for handling each
func (s *Server) serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return errors.Wrap(err, "failed to accept")
		}

		go s.Handle(conn)
	}
}

func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	if err := s.handleAuth(conn); err != nil {
		log.Printf("failed to authenticate the request, err: %v", err)
		return
	}

	processRequest(conn)
}

// handleAuth reads auth request and calls an appropriate
// authenticator if found and send auth failure response
// otherwise
func (s *Server) handleAuth(conn net.Conn) error {
	headerBuf := make([]byte, 2)
	_, err := conn.Read(headerBuf)
	if err != nil {
		return err
	}

	if int(headerBuf[0]) != socks5Version {
		return fmt.Errorf("the requested proxy version %d is not supported", int(headerBuf[0]))
	}

	nMethods := int(headerBuf[1])

	authMethodsBuf := make([]byte, nMethods)
	_, err = conn.Read(authMethodsBuf)
	if err != nil {
		return err
	}

	// authenticate with the first supported method
	for i := 0; i < nMethods; i += 1 {
		authenticator := getAuthenticator(int(authMethodsBuf[i]))
		if authenticator != nil {
			if err = authenticator.Authenticate(conn); err != nil {
				return errors.Wrap(err, "failed to authenticate")
			}
			return nil
		}
	}

	_, err = conn.Write([]byte{subnegotiationVersion, noAcceptableMethod})
	if err != nil {
		return err
	}

	return fmt.Errorf("no valid method found to authenticate")
}

func processRequest(conn net.Conn) {
	header := make([]byte, 3)
	_, err := conn.Read(header)
	if err != nil {
		log.Printf("failed to read from conn, err: %v", err)
		return
	}
	if int(header[0]) != socks5Version {
		log.Printf("the requested proxy version %d is not supported", int(header[0]))
		return
	}

	dstAddr, err := readAddrPort(conn)
	if err != nil {
		if err == ErrInvalidAddrType {
			sendReply(conn, replyAddressTypeNotSupported, "")
		}
		log.Printf("failed to read address & port, err: %v", err)
		return
	}

	var dstIP net.IP
	switch dstAddr.addrType {
	case addrTypeIPv4, addrTypeIPv6:
		dstIP = dstAddr.ip
	case addrTypeFQDN:
		dstIP, err = resolveAddr(dstAddr.name)
		if err != nil {
			log.Printf("failed to resolve addr, err: %v", err)
			return
		}
	}

	switch int(header[1]) {
	case cmdConnect:
		handleConnect(conn, dstIP, dstAddr.port)
	case cmdBind:
		handleBind(conn, dstIP, dstAddr.port)
	case cmdUDPAssociate:
		handleUDPAssociate(conn, dstIP, dstAddr.port)
	default:
		sendReply(conn, replyCommandNotSupported, "")
		return
	}
}

func handleConnect(conn net.Conn, dstIP net.IP, dstPort uint16) {
	remoteConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", dstIP.String(), dstPort))
	if err != nil {
		log.Printf("failed to dial remote server, err: %v", err)
		sendReply(conn, replyHostUnreachable, "")
		return
	}

	localAddr := remoteConn.LocalAddr().(*net.TCPAddr)
	sendReply(conn, replySucceeded, localAddr.String())
	pipeConnections(conn, remoteConn)
}

func pipeConnections(src, dst net.Conn) {
	g := errgroup.Group{}
	g.Go(func() error {
		_, err := io.Copy(src, dst)
		return err
	})
	g.Go(func() error {
		_, err := io.Copy(dst, src)
		return err
	})
	if err := g.Wait(); err != nil {
		log.Printf("connection pipe failed, err: %v", err)
	}
}

func handleBind(conn net.Conn, dstIP net.IP, dstPort uint16) {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", dstIP.String(), dstPort))
	if err != nil {
		log.Printf("failed to listen to the requested addr, err: %v", err)
		sendReply(conn, replyGeneralSOCKSServerFailure, "")
		return
	}

	//localAddr := conn.LocalAddr().(*net.TCPAddr)
	sendReply(conn, replySucceeded, ln.Addr().String())

	server, err := ln.Accept()
	if err != nil {
		log.Printf("failed to accept new connection, err: %v", err)
		sendReply(conn, replyGeneralSOCKSServerFailure, "")
		return
	}

	serverAddr := server.LocalAddr().(*net.TCPAddr)
	sendReply(conn, replySucceeded, serverAddr.String())
	fmt.Println(4)
	pipeConnections(conn, server)
}

// handleUDPAssociate handles the UDPAssociate cmd.
// Note: As per the RFC-1928 we don't notify the clients
// whether we relay or drop packets
func handleUDPAssociate(conn net.Conn, dstIP net.IP, dstPort uint16) {
	udpConn, err := net.ListenPacket("udp", net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort))))
	if err != nil {
		log.Printf("failed to create udp listener, err: %v", err)
		return
	}
	defer udpConn.Close()

	bindIP := conn.LocalAddr().(*net.TCPAddr).IP
	bindPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	sendReply(conn, replySucceeded, net.JoinHostPort(bindIP.String(), strconv.Itoa(bindPort)))

	go monitorConn(conn, udpConn)

	var (
		buf        = make([]byte, maxUDPPacketSize)
		clientAddr *net.UDPAddr
		serverAddr *net.UDPAddr
	)
	for {
		n, addr, err := udpConn.ReadFrom(buf[:])
		if err != nil {
			log.Printf("failed to read from udp connection, err: %v", err)
			return
		}
		if clientAddr == nil {
			clientAddr = addr.(*net.UDPAddr)
		}

		switch {
		case clientAddr != nil && addr.String() == clientAddr.String():
			// UDP packets from the client have UDP-Associate header
			if err := validateUDPAssociatePacket(buf[:n]); err != nil {
				log.Printf("invalid packet, err: %v", err)
				return
			}
			uaPacket, err := parseUDPAssociatePacket(buf[:n])
			if err != nil {
				log.Printf("failed to parse udp associate packet, err: %v", err)
				return
			}
			serverNetAddr, err := getNetAddr("udp", uaPacket.DstIP, int(uaPacket.DstPort))
			if err != nil {
				log.Printf("failed to get server net addr, err: %v", err)
				return
			}
			serverAddr = serverNetAddr.(*net.UDPAddr)
			if err != nil {
				log.Printf("failed to parse UDP Associate Packet, err: %v", err)
				return
			}
			_, err = udpConn.WriteTo(uaPacket.Data, serverAddr)
			if err != nil {
				log.Printf("failed to write to serverAddr, err: %v", err)
				break
			}
		case serverAddr != nil && addr.String() == serverAddr.String():
			// UDP packets sent to the client must have UDP-Associate header
			uaPacket, err := packUDPAssociatePacket(buf[:n], serverAddr)
			if err != nil {
				log.Printf("failed to packed udp packet, err: %v", err)
				break
			}
			_, err = udpConn.WriteTo(uaPacket, clientAddr)
			if err != nil {
				log.Printf("failed to write to serverAddr, err: %v", err)
				break
			}
		default:
			log.Printf("invalid DstIP: %s", addr.String())
			continue
		}

	}
}

func packUDPAssociatePacket(data []byte, addr *net.UDPAddr) ([]byte, error) {
	packedWriter := bytes.NewBuffer(make([]byte, 0))
	// RSV and FRAG
	packedWriter.Write([]byte{0, 0, 0})
	if err := writeUDPAssociateAddr(packedWriter, addr); err != nil {
		return nil, err
	}
	packedWriter.Write(data)
	return packedWriter.Bytes(), nil
}

func writeUDPAssociateAddr(writer io.Writer, addr *net.UDPAddr) error {
	var (
		addrType AddrType
		ip       []byte
	)
	if addr.IP.To4() != nil {
		addrType = addrTypeIPv4
		ip = addr.IP.To4()
	} else {
		addrType = addrTypeIPv6
		ip = addr.IP.To16()
	}

	_, err := writer.Write([]byte{uint8(addrType)})
	if err != nil {
		return err
	}

	_, err = writer.Write(ip)
	if err != nil {
		return err
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(addr.Port))
	_, err = writer.Write(portBytes)
	return err
}

func validateUDPAssociatePacket(data []byte) error {
	if len(data) < minUDPAssociatePacketSize {
		return fmt.Errorf("packet length %d is too small", len(data))
	}
	if int(data[2]) != udpAssociateNoFrag {
		return fmt.Errorf("fragmentation is requested but not supported")
	}
	return nil
}

func parseUDPAssociatePacket(data []byte) (*UDPAssociatePacket, error) {
	uaPacket := &UDPAssociatePacket{}
	uaPacket.AddrType = AddrType(data[3])
	addrLen, err := getAddrLen(uaPacket.AddrType)
	if err != nil {
		log.Printf("failed to get addr len, err: %v", err)
		return nil, err
	}
	var endOfAddr = 4 + addrLen
	dstAddr := data[4:endOfAddr]
	if uaPacket.AddrType == addrTypeFQDN {
		addrLen = data[4]
		endOfAddr = 5 + addrLen
		dstAddr = data[5:endOfAddr]
		ipAddr, err := net.ResolveIPAddr("ip", string(dstAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to read address, %w", err)
		}
		dstAddr = ipAddr.IP
	}
	uaPacket.DstIP = dstAddr
	uaPacket.DstPort = binary.BigEndian.Uint16(data[endOfAddr : endOfAddr+2])
	uaPacket.Data = data[endOfAddr+2:]

	return uaPacket, nil
}

// monitorConn monitors the tcp connection and closes the udp connection
// as soon as the tcp connection encounters an error.
// Based on RFC-1928:
// A UDP association terminates when the TCP connection that the
// UDP ASSOCIATE request arrived on terminates.
func monitorConn(conn net.Conn, packetConn net.PacketConn) {
	for {
		buf := make([]byte, 1)
		if _, err := conn.Read(buf[:]); err != nil {
			packetConn.Close()
			return
		}
	}
}

func sendReply(conn net.Conn, rep uint8, addr string) {
	if _, err := conn.Write([]byte{socks5Version, rep, 0}); err != nil {
		log.Printf("failed to write reply prefix, err: %v", err)
	}

	var err error
	if rep == replySucceeded {
		err = writeAddrPort(conn, addr, false)
	} else {
		_, err = conn.Write([]byte{0, 1, 0, 0, 0})
	}
	if err != nil {
		log.Printf("failed to write reply, err: %v", err)
	}
}
