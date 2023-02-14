package gosocks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
)

type contextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type proxyAuth struct {
	username    string
	password    string
	usernameLen int
	passwordLen int
}

type Dialer struct {
	proxyAddr string
	proxyAuth *proxyAuth

	// socks5h delegates DNS resolution to proxy server but
	// socks5 does that locally
	// https://superuser.com/a/1762355/956392
	localResolve bool
}

func NewDialer(addr string) (*Dialer, error) {
	dialer := &Dialer{}
	parsedUrl, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	switch parsedUrl.Scheme {
	case "socks5h":
	case "socks5":
		dialer.localResolve = true
	default:
		return nil, fmt.Errorf("invalid url scheme %s", parsedUrl.Scheme)
	}

	if parsedUrl.User != nil {
		dialer.proxyAuth = &proxyAuth{}
		dialer.proxyAuth.username = parsedUrl.User.Username()
		dialer.proxyAuth.usernameLen = len(dialer.proxyAuth.username)
		dialer.proxyAuth.password, _ = parsedUrl.User.Password()
		dialer.proxyAuth.passwordLen = len(dialer.proxyAuth.password)

		if dialer.proxyAuth.usernameLen > 255 {
			return nil, fmt.Errorf("too long username length %d", len(dialer.proxyAuth.username))
		}
		if dialer.proxyAuth.passwordLen > 255 {
			return nil, fmt.Errorf("too long password length %d", len(dialer.proxyAuth.password))
		}
	}

	dialer.proxyAddr = parsedUrl.Host
	if parsedUrl.Port() == "" {
		dialer.proxyAddr = net.JoinHostPort(parsedUrl.Host, strconv.Itoa(defaultPort))
	}

	return dialer, nil
}

var _ contextDialer = &Dialer{}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.dialProxyServer(ctx)
	if err != nil {
		return nil, err
	}

	err = d.negotiateAuthentication(conn)
	if err != nil {
		return nil, err
	}

	var cmd int
	switch network {
	case "tcp", "tcp4", "tcp6":
		cmd = cmdConnect
	case "udp", "udp4", "udp6":
		cmd = cmdUDPAssociate
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}

	conn, err = d.negotiateCmd(cmd, conn, addr)

	return conn, err
}

func (d *Dialer) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("network is not supported")
	}
	return &listener{
		dialer:  d,
		ctx:     ctx,
		network: network,
		address: address,
	}, nil
}

func (d *Dialer) negotiateCmd(cmd int, conn net.Conn, addr string) (net.Conn, error) {
	// write VER,CMD,RSV
	_, err := conn.Write([]byte{socks5Version, byte(cmd), 0})
	if err != nil {
		return nil, err
	}

	// write ATYP,DST.ADDR,DST.PORT
	if cmd == cmdUDPAssociate {
		// If the client is not in possession of the information at the time of the
		// UDP ASSOCIATE, the client MUST use a port number and address of all zeros.
		err = writeAddrPort(conn, ":0", d.localResolve)
	} else {
		err = writeAddrPort(conn, addr, d.localResolve)
	}
	if err != nil {
		return nil, err
	}

	// read VER,REP,RSV
	respHeaderBytes := make([]byte, 3)
	_, err = io.ReadFull(conn, respHeaderBytes)
	if err != nil {
		return nil, err
	}
	if respHeaderBytes[0] != socks5Version {
		return nil, fmt.Errorf("invalid proxy version :%d", respHeaderBytes[0])
	}
	if respHeaderBytes[1] != replySucceeded {
		return nil, fmt.Errorf("proxy request failed with reply :%d", respHeaderBytes[1])
	}

	// read ATYP,BND.ADDR,BND.PORT
	proxyAddr, err := readAddrPort(conn)
	if err != nil {
		return nil, err
	}

	// no more action for CONNECT and BIND as they use the underlying connection
	switch cmd {
	case cmdConnect, cmdBind:
		return conn, nil
	case cmdUDPAssociate:
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		portInt, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}

		udpConn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return nil, err
		}
		associateConn, err := NewUDPAssociateConn(udpConn, proxyAddr, &net.UDPAddr{
			IP:   net.ParseIP(host),
			Port: portInt,
		})
		if err != nil {
			return nil, err
		}

		go monitorConn(conn, associateConn)

		return associateConn, nil
	default:
		return nil, fmt.Errorf("invalid cmd %d", cmd)
	}
}

func (d *Dialer) dialProxyServer(ctx context.Context) (net.Conn, error) {
	var netDialer net.Dialer
	return netDialer.DialContext(ctx, "tcp", d.proxyAddr)
}

func (d *Dialer) negotiateAuthentication(conn net.Conn) error {
	var err error
	if d.proxyAuth == nil {
		_, err = conn.Write([]byte{socks5Version, 1, noAuthMethod})
	} else {
		_, err = conn.Write([]byte{socks5Version, 2, userPassMethod, noAuthMethod})
	}
	if err != nil {
		return err
	}

	methodResponseBuf := make([]byte, 2)
	_, err = io.ReadFull(conn, methodResponseBuf)
	if err != nil {
		return err
	}
	if methodResponseBuf[0] != socks5Version {
		return fmt.Errorf("invalid proxy version: %d", methodResponseBuf[0])
	}
	switch methodResponseBuf[1] {
	case noAuthMethod:
	case userPassMethod:
		reqBytes := make([]byte, 0)
		reqBytes = append(reqBytes, subnegotiationVersion)
		reqBytes = append(reqBytes, byte(d.proxyAuth.usernameLen))
		reqBytes = append(reqBytes, []byte(d.proxyAuth.username)...)
		reqBytes = append(reqBytes, byte(d.proxyAuth.passwordLen))
		reqBytes = append(reqBytes, []byte(d.proxyAuth.password)...)
		_, err = conn.Write(reqBytes)
		if err != nil {
			return err
		}

		respBuf := make([]byte, 2)
		_, err = io.ReadFull(conn, respBuf)
		if err != nil {
			return err
		}
		if respBuf[0] != subnegotiationVersion {
			return fmt.Errorf("invalid subnegotiation version %d", respBuf[0])
		}
		if respBuf[1] != authStatusSuccess {
			return fmt.Errorf("authentication failed with status %d", respBuf[1])
		}
	default:
		return fmt.Errorf("invalid method: %d", methodResponseBuf[1])
	}
	return nil
}

type listener struct {
	ctx     context.Context
	dialer  *Dialer
	network string
	address string
}

func (l *listener) Accept() (net.Conn, error) {
	proxyConn, err := l.dialer.dialProxyServer(l.ctx)
	if err != nil {
		return nil, err
	}

	err = l.dialer.negotiateAuthentication(proxyConn)
	if err != nil {
		return nil, err
	}

	conn, err := l.dialer.negotiateCmd(cmdBind, proxyConn, l.address)
	if err != nil {
		return nil, fmt.Errorf("failed to make initial negotiation, %w", err)
	}

	return conn, nil
}

func (l *listener) Close() error {
	return nil
}

func (l *listener) Addr() net.Addr {
	return nil
}
