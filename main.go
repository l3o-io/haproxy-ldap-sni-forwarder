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
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
)

/*
Application BER Types Used in LDAP can be found here:

https://ldap.com/ldapv3-wire-protocol-reference-asn1-ber/

 */
func handleConnection(c net.Conn) {
	var (
		ioff = 0
		total = 0
		msgid byte
		msglen byte
		berop byte
		beroplen byte
		resultcode byte
		sniname string

		buf_ldap_extop_req []byte
		bk_c net.Conn
	)

	buf := make([]byte, 1024)

	for {
		n, err := c.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break
		}

		total += n
		if n >= 5 {
			if buf[0] == 0x16 {  // TLS Handshake
				fmt.Printf("TLS Handshake - len: %d\n", buf[1])
				if buf[5] == 0x1 {
					ioff = 1 + 5 + 3 + 2 + 32
					fmt.Println(" * Client Hello")
					fmt.Printf("    * Session-ID length: %d\n", buf[ioff])
					ioff += 1 + int(buf[ioff])  // Session-ID length
					cipherlen := (int(buf[ioff]) << 8) + int(buf[ioff + 1])
					fmt.Printf("    * Cipher-Suites length: %d\n", cipherlen)
					ioff += 2 + cipherlen
					fmt.Printf("    * Compression method length: %d\n", buf[ioff])
					ioff += 1 + int(buf[ioff])
					extensionlen := (int(buf[ioff]) << 8) + int(buf[ioff + 1])
					fmt.Printf("    * Extensions length: %d\n", extensionlen)
					ioff += 2
					extype := (int(buf[ioff]) << 8) + int(buf[ioff + 1])
					extlen := (int(buf[ioff + 2]) << 8) + int(buf[ioff + 3])
					ioff += 2 + 2
					fmt.Printf("    * Extension type: %d length: %d\n", extype, extlen)
					if extype == 0 {
						fmt.Println("      * server_name")
						fmt.Printf("%#x %#x %#x %#x\n", buf[ioff], buf[ioff + 1], buf[ioff + 2], buf[ioff + 3])
						// assuming one sni entry of type hostname
						ioff += 2
						snametype := buf[ioff]
						ioff++
						if snametype == 0 {
							snilen := (int(buf[ioff]) << 8) + int(buf[ioff + 1])
							fmt.Printf("        * SNI type: host_name (type: %d) length: %d\n", snametype, snilen)
							ioff += 2
							sniname = string(buf[ioff:ioff+snilen])
							fmt.Println("        * SNI server_name:", sniname)
							if buf_ldap_extop_req != nil {
								fmt.Println("PROXY LDAP REQ")
								bk_c, err = net.Dial("tcp", sniname + ":389")
								if err != nil {
									fmt.Println("dial error:", err)
									return
								}
								defer bk_c.Close()

								bk_c.Write(buf_ldap_extop_req)
								tmpbuf := make([]byte, 1024)
								bk_c.Read(tmpbuf)
								if tmpbuf[0] == 0x30 && tmpbuf[5] == 0x78 {
									fmt.Printf("sbuf: %#x %#x\n", tmpbuf[0], tmpbuf[5])
									fmt.Println("surpressed LDAP_START_TLS_OID ExtendedResponse")
								}
							}
						}
						//fmt.Printf("%#x %#x %#x %#x\n", buf[ioff], buf[ioff + 1], buf[ioff + 2], buf[ioff + 3])
					}
				}
			}
			if buf[0] == 0x30 {  // LDAP operation
				msglen = buf[1]
				msgid = buf[4]
				berop = buf[5]
				beroplen = buf[6]
				/*
				7: 0a
				8: 01
				 */
				resultcode = byte(0)
				fmt.Printf("LDAP [%d] len: %d opcode %#x\n", msgid, msglen, berop)
				if berop == 0x77 {
					fmt.Printf(" * ExtendedRequest len: %d resultcode: %d\n", beroplen, resultcode)
					if n - 22 > 0 {
						oid := string(buf[n-22:n])
						if oid == "1.3.6.1.4.1.1466.20037" { // LDAP_START_TLS_OID
							//var hello *tls.ClientHelloInfo
							fmt.Println("    * LDAP_START_TLS_OID")
							// ExtendedResponse berop 0x78 (byte no. 6 idx 5)
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
							resp[4] = msgid
							buf_ldap_extop_req = make([]byte, n)
							copy(buf_ldap_extop_req, buf)
							c.Write(resp)
							//tls.Server(c, &tls.Config{
							//	GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
							//		hello = new(tls.ClientHelloInfo)
							//		*hello = *argHello
							//		return nil, nil
							//	},
							//}).Handshake()
							//c.readClientHello()
							//fmt.Println("ServerName: ", hello.ServerName)
						}
					}
				}
			}
			fmt.Println(hex.EncodeToString(buf[:n]))
			if bk_c != nil {
				bk_c.Write(buf[:n])
				n, err = bk_c.Read(buf)
				//if buf[0] == 0x30 && buf[5] == 0x78 {
				//	fmt.Printf("sbuf: %#x %#x\n", buf[0], buf[5])
				//	fmt.Println("surpressed LDAP_START_TLS_OID ExtendedResponse")
				//	continue
				//}
				c.Write(buf[:n])
				break
			} else {
				fmt.Println("backend connection is not open")
			}
		}
		fmt.Println(n)

	}
	fmt.Println("total: ", total)
	fmt.Println("SNI detection finished")
	fmt.Println("  ServerName:", sniname)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(c, bk_c)
		c.(*net.TCPConn).CloseWrite()
		wg.Done()
	}()
	go func() {
		io.Copy(bk_c, c)
		bk_c.(*net.TCPConn).CloseWrite()
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
