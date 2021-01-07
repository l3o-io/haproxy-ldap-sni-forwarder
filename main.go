// haproxy-ldap-sni-forwarder, proxies incoming LDAP traffic based on
// TLS SNI when using LDAP_START_TLS_OID extended berop requests
// Copyright (C) 2021  Christian Felder
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)


const OP_TLS = 0x16
const OP_LDAP = 0x30
const BEROP_EXTENDED_REQUEST = 0x77
const BEROP_EXTENDED_RESPONSE = 0x78
const LDAP_START_TLS_OID = "1.3.6.1.4.1.1466.20037"


type readOnlyConn struct {
	buf []byte
}
func (conn readOnlyConn) Read(p []byte) (int, error)         { return copy(p, conn.buf), nil }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }


/*
Application BER Types Used in LDAP can be found here:

https://ldap.com/ldapv3-wire-protocol-reference-asn1-ber/

 */
func handleConnection(c net.Conn) {
	var (
		backendConnection net.Conn
		clientReader io.Reader
	)

	buf := make([]byte, 1024)

	peekedBytes := new(bytes.Buffer)
	peekReader := io.TeeReader(c, peekedBytes)
	beropBytes := 0

	for {
		n, err := peekReader.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break
		}

		if n >= 7 {
			if buf[0] == OP_LDAP {  // LDAP operation
				type ldapPacket struct {
					Length    byte
					MessageID byte
					BerOp     byte
				}

				packet := ldapPacket{Length: buf[1], MessageID: buf[4], BerOp: buf[5]}
				if packet.BerOp == BEROP_EXTENDED_REQUEST {
					if n < 22 {
						continue
					}
					oid := string(buf[n-22 : n])
					if oid == LDAP_START_TLS_OID {
						// pretend we support TLS
						resp := []byte{0x30, 0x5f, 0x2, 0x1, 0x1, 0x78, 0x5a, 0xa,
							0x1, 0x0, 0x4, 0x0, 0x4, 0x3b, 0x53, 0x74,
							0x61, 0x72, 0x74, 0x20, 0x54, 0x4c, 0x53, 0x20,
							0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x20,
							0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x65, 0x64,
							0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
							0x77, 0x69, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x20,
							0x74, 0x6f, 0x20, 0x6e, 0x65, 0x67, 0x6f, 0x74,
							0x69, 0x61, 0x74, 0x65, 0x20, 0x53, 0x53, 0x4c,
							0x2e, 0x8a, 0x16, 0x31, 0x2e, 0x33, 0x2e, 0x36,
							0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31,
							0x34, 0x36, 0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37}
						// update response messageID with requested one
						resp[4] = packet.MessageID
						c.Write(resp)
						beropBytes = n
					}
				}
			} else if buf[0] == OP_TLS {  // TLS Handshake
				var hello *tls.ClientHelloInfo
				err := tls.Server(readOnlyConn{buf: buf}, &tls.Config{
					GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
						hello = new(tls.ClientHelloInfo)
						*hello = *argHello
						return nil, nil
					},
				}).Handshake()

				if hello == nil {
					fmt.Println("error on intercepting client hello (tls handshake)")
					return
				}
				// got client hello
				backendConnection, err = net.Dial("tcp", net.JoinHostPort(hello.ServerName, "389"))
				if err != nil {
					fmt.Println("error on creating backend connection", err)
					return
				}
				defer backendConnection.Close()

				fmt.Println(backendConnection.LocalAddr().String(), hello.ServerName)
				// send intercepted LDAP_START_TLS_OID berop extended request to server
				// but intercept extended response because we already pretended tls support before
				backendConnection.Write(peekedBytes.Next(beropBytes))
				backendConnection.Read(buf)  // suppress berop extended response
				if buf[0] == OP_LDAP && buf[5] == BEROP_EXTENDED_RESPONSE {
					// concat peeked tls request and client connection for further processing/proxying
					clientReader = io.MultiReader(peekedBytes, c)
					break
				}
			}
		}
	}
	// SNI detection finished proxy all requests

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(c, backendConnection)
		c.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()
	go func() {
		io.Copy(backendConnection, clientReader)
		backendConnection.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()

	wg.Wait()

	c.Close()
}


func main() {
	fmt.Println("ldap sni proxy server listening on port 3389")
	l, err := net.Listen("tcp4", ":3389")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(c)
	}
}
