package gosocks5

import (
	"fmt"
	"github.com/pkg/errors"
	"log"
	"net"
)

type Authenticator interface {
	Authenticate(conn net.Conn) error
}

type NoAuthAuthenticator struct{}

var _ Authenticator = &NoAuthAuthenticator{}

func (na *NoAuthAuthenticator) Authenticate(conn net.Conn) (finalErr error) {
	_, err := conn.Write([]byte{socks5Version, noAuthMethod})
	if err != nil {
		return err
	}
	return nil
}

type UserPassAuthenticator struct {
	// todo: Credentials should be filled somewhere
	Credentials map[string]string
}

var _ Authenticator = &UserPassAuthenticator{}

func (up *UserPassAuthenticator) Authenticate(conn net.Conn) (finalErr error) {
	defer func() {
		if finalErr == nil {
			if _, err := conn.Write([]byte{subnegotiationVersion, authStatusSuccess}); err != nil {
				log.Printf("failed to write auth success response, err: %v", err)
			}
		} else {
			if _, err := conn.Write([]byte{subnegotiationVersion, authStatusFailure}); err != nil {
				log.Printf("failed to write auth failure response, err: %v", err)
			}
		}
	}()

	_, err := conn.Write([]byte{socks5Version, userPassMethod})
	if err != nil {
		return errors.Wrap(err, "failed to write selected auth method")
	}

	subnegotiationVersionBuf := make([]byte, 1)
	if _, err = conn.Read(subnegotiationVersionBuf); err != nil {
		return errors.Wrap(err, "failed to read subnegotiation version")
	}
	if int(subnegotiationVersionBuf[0]) != subnegotiationVersion {
		return fmt.Errorf("unexpected subnegotitation version %d", subnegotiationVersionBuf[0])
	}
	usernameLenBuf := make([]byte, 1)
	if _, err = conn.Read(usernameLenBuf); err != nil {
		return errors.Wrap(err, "failed to read username len")
	}
	usernameBuf := make([]byte, int(usernameLenBuf[0]))
	if _, err = conn.Read(usernameBuf); err != nil {
		return errors.Wrap(err, "failed to read username")
	}
	username := string(usernameBuf)
	storedPassword, ok := up.Credentials[username]
	if !ok {
		return fmt.Errorf("username %s doesn't exist", username)
	}
	passwordLenBuf := make([]byte, 1)
	if _, err = conn.Read(passwordLenBuf); err != nil {
		return errors.Wrap(err, "failed to read password len")
	}
	passwordBuf := make([]byte, int(passwordLenBuf[0]))
	if _, err = conn.Read(passwordBuf); err != nil {
		return errors.Wrap(err, "failed to read password")
	}
	if storedPassword != string(passwordBuf) {
		return fmt.Errorf("password doesn't match for username %s", username)
	}
	return nil
}

func getAuthenticator(authMethod int) Authenticator {
	authenticators := map[int]Authenticator{
		0: &NoAuthAuthenticator{},
		2: &UserPassAuthenticator{},
	}

	if authenticator, ok := authenticators[authMethod]; ok {
		return authenticator
	}
	return nil
}
