package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	selectedMethod, err := negotiateAuth(conn)
	if err != nil {
		log.Println("auth negotiation failed:", err)
		return
	}

	log.Println("selected method:", selectedMethod)

	if selectedMethod == 0x02 {

		err = authenticateUserPass(conn)
		if err != nil {
			log.Println("username/password auth failed:", err)
			return
		}
	}

	targetConn, err := handleConnect(conn)
	if err != nil {
		log.Println("connect handling failed:", err)
		return
	}

	defer targetConn.Close()

	relay(conn, targetConn)
}
func negotiateAuth(conn net.Conn) (byte, error) {

	header := make([]byte, 2)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		return 0, err
	}

	version := header[0]
	nMethods := header[1]

	log.Println("version:", version)
	log.Println("nMethods:", nMethods)

	methods := make([]byte, nMethods)

	_, err = io.ReadFull(conn, methods)
	if err != nil {
		return 0, err
	}

	log.Println("methods:", methods)

	proxyUser := os.Getenv("PROXY_USER")

	// AUTH REQUIRED
	if proxyUser != "" {

		for _, method := range methods {

			if method == 0x02 {

				_, err = conn.Write([]byte{0x05, 0x02})
				if err != nil {
					return 0, err
				}

				log.Println("selected username/password auth")

				return 0x02, nil
			}
		}

		_, err = conn.Write([]byte{0x05, 0xFF})
		return 0, err
	}

	// NO AUTH MODE
	for _, method := range methods {

		if method == 0x00 {

			_, err = conn.Write([]byte{0x05, 0x00})
			if err != nil {
				return 0, err
			}

			log.Println("selected no-auth")

			return 0x00, nil
		}
	}

	_, err = conn.Write([]byte{0x05, 0xFF})

	return 0, err
}
func authenticateUserPass(conn net.Conn) error {

	header := make([]byte, 2)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		return err
	}

	version := header[0]
	usernameLength := header[1]

	log.Println("auth version:", version)

	usernameBytes := make([]byte, usernameLength)

	_, err = io.ReadFull(conn, usernameBytes)
	if err != nil {
		return err
	}

	username := string(usernameBytes)

	passwordLength := make([]byte, 1)

	_, err = io.ReadFull(conn, passwordLength)
	if err != nil {
		return err
	}

	passwordBytes := make([]byte, passwordLength[0])

	_, err = io.ReadFull(conn, passwordBytes)
	if err != nil {
		return err
	}

	password := string(passwordBytes)

	log.Println("username:", username)
	log.Println("password:", password)

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if username == expectedUser && password == expectedPass {

		_, err = conn.Write([]byte{0x01, 0x00})

		log.Println("authentication successful")

		return err
	}

	_, err = conn.Write([]byte{0x01, 0x01})

	log.Println("authentication failed")

	return fmt.Errorf("invalid credentials")
}
func handleConnect(conn net.Conn) (net.Conn, error) {
	requestHeader := make([]byte, 4)

	_, err := io.ReadFull(conn, requestHeader)
	if err != nil {
		return nil, err
	}

	version := requestHeader[0]
	cmd := requestHeader[1]
	atyp := requestHeader[3]

	log.Println("request version:", version)
	log.Println("cmd:", cmd)
	log.Println("address type:", atyp)
	if cmd != 0x01 {
		return nil, fmt.Errorf("unsupported command")
	}
	if atyp == 0x01 {
		addr := make([]byte, 4)

		_, err = io.ReadFull(conn, addr)
		if err != nil {
			return nil, err
		}

		ip := net.IP(addr)

		portBytes := make([]byte, 2)

		_, err = io.ReadFull(conn, portBytes)
		if err != nil {
			return nil, err
		}

		port := int(portBytes[0])<<8 | int(portBytes[1])

		log.Println("destination IP:", ip.String())
		log.Println("destination port:", port)

		targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip.String(), port))
		if err != nil {

			reply := []byte{
				0x05,
				0x01,
				0x00,
				0x01,
				0, 0, 0, 0,
				0, 0,
			}

			conn.Write(reply)

			return nil, err
		}

		reply := []byte{
			0x05,
			0x00,
			0x00,
			0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}

		_, err = conn.Write(reply)
		if err != nil {
			targetConn.Close()
			return nil, err
		}

		log.Println("connected to target")

		return targetConn, nil
	}
	if atyp == 0x03 {

		length := make([]byte, 1)

		_, err = io.ReadFull(conn, length)
		if err != nil {
			return nil, err
		}

		domainBytes := make([]byte, length[0])

		_, err = io.ReadFull(conn, domainBytes)
		if err != nil {
			return nil, err
		}

		domain := string(domainBytes)

		portBytes := make([]byte, 2)

		_, err = io.ReadFull(conn, portBytes)
		if err != nil {
			return nil, err
		}

		port := int(portBytes[0])<<8 | int(portBytes[1])

		log.Println("destination domain:", domain)
		log.Println("destination port:", port)

		targetConn, err := net.Dial(
			"tcp",
			fmt.Sprintf("%s:%d", domain, port),
		)

		if err != nil {

			reply := []byte{
				0x05,
				0x01,
				0x00,
				0x01,
				0, 0, 0, 0,
				0, 0,
			}

			conn.Write(reply)

			return nil, err
		}

		reply := []byte{
			0x05,
			0x00,
			0x00,
			0x01,
			0, 0, 0, 0,
			0, 0,
		}

		_, err = conn.Write(reply)
		if err != nil {
			targetConn.Close()
			return nil, err
		}

		log.Println("connected to target domain")

		return targetConn, nil
	}

	return nil, fmt.Errorf("unsupported address type")
}
func relay(client net.Conn, target net.Conn) {
	go io.Copy(target, client)
	io.Copy(client, target)
}
