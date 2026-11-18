// Package testdns provides a local DNS fixture for network integration tests.
package testdns

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

type Server struct {
	Address    string
	UDPQueries atomic.Int32
	TCPQueries atomic.Int32
	UDPSource  atomic.Value // string: last client's IP
	TCPSource  atomic.Value
}

// Start answers A queries with ip. truncate exercises UDP-to-TCP DNS fallback.
func Start(t testing.TB, ip [4]byte, truncate bool) *Server {
	return StartRecords(t, truncate, func(q dnsmessage.Question) []dnsmessage.Resource {
		if q.Type != dnsmessage.TypeA {
			return nil
		}
		return []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: ip}}}
	})
}

// StartRecords serves records supplied by answer for each DNS question.
func StartRecords(t testing.TB, truncate bool, answer func(dnsmessage.Question) []dnsmessage.Resource) *Server {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); udp.Close() })
	s := &Server{Address: ln.Addr().String()}
	response := func(b []byte, truncated bool) []byte {
		var q dnsmessage.Message
		if q.Unpack(b) != nil || len(q.Questions) != 1 {
			return nil
		}
		r := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true, Truncated: truncated}, Questions: q.Questions}
		if !truncated {
			r.Answers = answer(q.Questions[0])
		}
		data, _ := r.Pack()
		return data
	}
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(a.String())
			s.UDPSource.Store(host)
			s.UDPQueries.Add(1)
			udp.WriteTo(response(b[:n], truncate), a)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			s.TCPSource.Store(host)
			go func() {
				defer c.Close()
				var length [2]byte
				if _, err := io.ReadFull(c, length[:]); err != nil {
					return
				}
				b := make([]byte, int(binary.BigEndian.Uint16(length[:])))
				if _, err := io.ReadFull(c, b); err != nil {
					return
				}
				s.TCPQueries.Add(1)
				data := response(b, false)
				binary.BigEndian.PutUint16(length[:], uint16(len(data)))
				c.Write(append(length[:], data...))
			}()
		}
	}()
	return s
}
