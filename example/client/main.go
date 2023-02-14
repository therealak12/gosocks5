package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"github.com/therealak12/gosocks5"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"time"
)

func main() {
	log.SetFlags(log.Lshortfile)

	socks5Dialer, err := gosocks5.NewDialer("socks5h://127.0.0.1:1080")
	if err != nil {
		log.Printf("failed to create dialer, err: %v", err)
		return
	}

	//exampleConnectCommand(socks5Dialer)

	exampleBindCommand(socks5Dialer)

	//exampleUDPAssociateCommand(socks5Dialer)
}

func exampleConnectCommand(socks5Dialer *gosocks5.Dialer) {
	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: socks5Dialer.DialContext,
		},
	}

	response, err := cli.Get("https://mocki.io/v1/d4867d8b-b5d5-4a48-a4ab-79131b5809b8")
	if err != nil {
		log.Printf("failed to get url, err: %v", err)
		return
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("failed to read response bytes, err: %v", err)
		return
	}

	log.Printf("got response: %s", string(responseBytes))
}

func exampleBindCommand(dialer *gosocks5.Dialer) {
	dial, err := gosocks5.NewDialer("socks5://" + "127.0.0.1:1080")
	if err != nil {
		log.Printf("failed to create dialer, %v", err)
		return
	}

	listener, err := dial.Listen(context.Background(), "tcp", ":10000")
	if err != nil {
		log.Printf("failed to listen, %v", err)
		return
	}
	go func() {
		if err := http.Serve(listener, nil); err != nil {
			log.Printf("http serve failed, %v", err)
		}
	}()
	time.Sleep(time.Second)
	resp, err := http.Get("http://127.0.0.1:10000")
	if err != nil {
		log.Printf("failed to get url, %v", err)
		return
	}
	resp.Body.Close()
}

func exampleUDPAssociateCommand(dialer *gosocks5.Dialer) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Printf("failed to ListenPacket, err: %v", err)
		return
	}
	defer packet.Close()

	go func() {
		var buf [math.MaxUint16 - 28]byte
		for {
			n, addr, err := packet.ReadFrom(buf[:])
			if err != nil {
				log.Printf("failed to read from packetConn, err: %v", err)
				return
			}
			_, err = packet.WriteTo(buf[:n], addr)
			if err != nil {
				log.Printf("failed to write to packetConn, err: %v", err)
				return
			}
		}
	}()

	conn, err := dialer.DialContext(context.Background(), "udp", packet.LocalAddr().String())
	if err != nil {
		log.Printf("failed to DialContext, err: %v", err)
		return
	}

	want := make([]byte, 1024)
	_, err = rand.Read(want)
	if err != nil {
		log.Printf("failed to fill want slice, err: %v", err)
		return
	}
	_, err = conn.Write(want)
	if err != nil {
		log.Printf("failed to write to conn, err: %v", err)
		return
	}

	got := make([]byte, len(want))
	_, err = conn.Read(got)
	if err != nil {
		log.Printf("failed to read from conn, err: %v", err)
		return
	}
	if !bytes.Equal(want, got) {
		log.Printf("want != equal, want: %v, got: %v", want, got)
	}
}
