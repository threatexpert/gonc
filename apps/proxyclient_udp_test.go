package apps

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestCreateSocks5UDPClientUnspecifiedAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	result := make(chan error, 1)
	go func() {
		result <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			var greeting [2]byte
			if _, err := io.ReadFull(conn, greeting[:]); err != nil {
				return err
			}
			methods := make([]byte, int(greeting[1]))
			if _, err := io.ReadFull(conn, methods); err != nil {
				return err
			}
			if _, err := conn.Write([]byte{5, 0}); err != nil {
				return err
			}
			var header [4]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				return err
			}
			if !bytes.Equal(header[:], []byte{5, 3, 0, 1}) {
				return fmt.Errorf("UDP ASSOCIATE header = %x, want 05030001", header)
			}
			var address [6]byte
			if _, err := io.ReadFull(conn, address[:]); err != nil {
				return err
			}
			if address != [6]byte{} {
				return fmt.Errorf("UDP ASSOCIATE address = %x, want 0.0.0.0:0", address)
			}
			port := udp.LocalAddr().(*net.UDPAddr).Port
			if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}); err != nil {
				return err
			}
			_, err = io.Copy(io.Discard, conn)
			return err
		}()
	}()
	config, err := ProxyClientConfigByCommandline(io.Discard, "socks5", "", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, clientErr := CreateSocks5UDPClient(config)
	if conn != nil {
		conn.Close()
	}
	if err := <-result; err != nil {
		t.Errorf("proxy: %v", err)
	}
	if clientErr != nil {
		t.Fatal(clientErr)
	}
}
