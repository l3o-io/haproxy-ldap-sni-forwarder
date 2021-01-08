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
	"io/ioutil"
	"net"
	"sync"
	"time"
	"gopkg.in/yaml.v2"
)


const OP_TLS = 0x16
const OP_LDAP = 0x30
const BEROP_EXTENDED_REQUEST = 0x77
const BEROP_EXTENDED_RESPONSE = 0x78
const LDAP_START_TLS_OID = "1.3.6.1.4.1.1466.20037"


const CLIENT_DEADLINE_SECONDS = 5
const BACKEND_TIMEOUT_SECONDS = 5


const DEFAULT_PORT = "3389"
const DEFAULT_HA_MAP = "/etc/haproxy/tcp2be.map"


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


type HaProxy struct {
	Host string
	Port string
	ControlPort string
}


type YamlConfig struct {
	Server struct {
		Host string
		Port string
	}
	HaProxy HaProxy
	Backend struct {
		Port string
		Hosts map[string]string
	}
}


/*
Application BER Types Used in LDAP can be found here:

https://ldap.com/ldapv3-wire-protocol-reference-asn1-ber/

 */
func handleConnection(c net.Conn, config *YamlConfig) {
	var (
		backendConnection net.Conn
		controlConnection net.Conn
		clientReader io.Reader
		hasHaProxy bool
	)
	defer c.Close()

	hasHaProxy = config.HaProxy != HaProxy{}

	err := c.SetReadDeadline(time.Now().Add(CLIENT_DEADLINE_SECONDS * time.Second))
	if err != nil {
		fmt.Println("Could not set client read deadline")
	}

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
			return
		}
		err = c.SetReadDeadline(time.Time{})
		if err != nil {
			fmt.Println("Could not reset client read deadline")
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
				var (
					hello *tls.ClientHelloInfo
					srcAddress *net.TCPAddr
					destAddress *net.TCPAddr
				)
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
				backendAddr, ok := config.Backend.Hosts[hello.ServerName]
				if ! ok {
					fmt.Println("error: cannot find backend for SNI server name", hello.ServerName)
					return
				}

				if hasHaProxy {
					l, err := net.Listen("tcp4", ":0")
					if err != nil {
						fmt.Println("error on getting source port for proxy connection", err)
						return
					}
					srcPort := fmt.Sprintf("%d", l.Addr().(*net.TCPAddr).Port)
					srcAddress, _ = net.ResolveTCPAddr("tcp", net.JoinHostPort("", srcPort))
					destAddress, _ = net.ResolveTCPAddr("tcp",
						net.JoinHostPort(config.HaProxy.Host, config.HaProxy.Port))
					l.Close()

					// create control connection
					controlConnection, err = net.DialTimeout("tcp",
						net.JoinHostPort(config.HaProxy.Host, config.HaProxy.ControlPort),
						BACKEND_TIMEOUT_SECONDS * time.Second)
					if err != nil {
						fmt.Println("error on creating control socket", err)
						return
					}
					// add map entry using control socket
					localAddress := net.JoinHostPort(controlConnection.LocalAddr().(*net.TCPAddr).IP.String(), srcPort)
					_, err = controlConnection.Write([]byte(fmt.Sprintf("add map %s %s %s\n",
						DEFAULT_HA_MAP, localAddress, backendAddr)))
					if err != nil {
						fmt.Println("error writing to control socket", err)
						return
					}
					_, err = controlConnection.Read(buf)
					if err != nil {
						fmt.Println("error reading from control socket", err)
						return
					}
				} else {
					srcAddress, _ = net.ResolveTCPAddr("tcp", net.JoinHostPort("", ":0"))
					destAddress, _ = net.ResolveTCPAddr("tcp",
						net.JoinHostPort(backendAddr, config.Backend.Port))
				}

				// connect to backend either via HaProxy or directly depending on configuration
				backendConnection, err = net.DialTCP("tcp", srcAddress, destAddress)
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

	if backendConnection != nil {
		localAddr := backendConnection.LocalAddr().String()
		fmt.Println(localAddr, "**closed connection**")
		controlConnection, err = net.DialTimeout("tcp",
			net.JoinHostPort(config.HaProxy.Host, config.HaProxy.ControlPort),
			BACKEND_TIMEOUT_SECONDS * time.Second)
		if err != nil {
			fmt.Println("error on creating control socket", err)
			return
		}
		_, err := controlConnection.Write([]byte(fmt.Sprintf("del map %s %s\n",
			DEFAULT_HA_MAP, localAddr)))
		if err != nil {
			fmt.Println("error writing to control socket", err)
			return
		}
		_, err = controlConnection.Read(buf)
		if err != nil {
			fmt.Println("error reading from control socket", err)
			return
		}
		controlConnection.Close()
	}
}


func main() {
	config := YamlConfig{}

	yamlFile, err := ioutil.ReadFile("conf.yaml")
	if err != nil {
		fmt.Println("error opening configuration file", err)
		return
	}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		fmt.Println("error reading configuration file", err)
		return
	}
	if len(config.Backend.Hosts) <= 0 {
		fmt.Println("error reading backends from configuration file")
		return
	}
	// Apply defaults if necessary
	if config.Server.Port == "" {
		config.Server.Port = DEFAULT_PORT
	}
	if config.Backend.Port == "" {
		config.Backend.Port = DEFAULT_PORT
	}

	listenAddr := net.JoinHostPort(config.Server.Host, config.Server.Port)
	fmt.Println("ldap sni proxy server listening on", listenAddr)
	l, err := net.Listen("tcp4", listenAddr)
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
		go handleConnection(c, &config)
	}
}
