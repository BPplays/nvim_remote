package main

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

func main() {
	// Define flags
	var ipAddr string
	var im_message string
	var password string
	var isServer bool
	var port int

	pflag.StringVarP(&ipAddr, "ip", "i", "", "IP address to send the UTF-8 string to")
	pflag.StringVarP(&im_message, "message", "m", "", "UTF-8 string to send")
	pflag.StringVarP(&password, "password", "p", "", "Password (hashed with SHA-512)")
	pflag.BoolVarP(&isServer, "receive", "d", false, "Receive UTF-8 string over TCP")
	pflag.IntVarP(&port, "port", "o", 32512, "Port number to use")
	pflag.Parse()

	if isServer {
		startServer(password, port)
	} else if ipAddr != "" {
		if im_message == "" {
			fmt.Println("Please provide a message with -m to send.")
			os.Exit(1)
		}
		if password == "" {
			fmt.Println("Please provide a password with -p.")
			os.Exit(1)
		}
		sendToIP(ipAddr, im_message, password, port)
	} else {
		fmt.Println("Please provide either an IP address with -i or use -d to receive data.")
	}
}

var im_map = map[string]string{
	"im-select":     "",
	"im-select-mac": "",
	"fcitx5-remote": "",
	"fcitx-remote":  "",
	"ibus":          "",
}

func parse_im(msg *string) {
	spl := strings.Split(*msg, ";")

	for _, v := range spl {
		if len(v) > 10000 {
			continue
		}

		kv := strings.Split(v, "=")
		if _, exists := im_map[kv[0]]; exists {
			// Set the value for the existing key
			im_map[kv[0]] = kv[1]
		}
	}

}

func startServer(expectedPassword string, port int) {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("Error starting TCP server: %v", err)
	}
	defer listener.Close()
	fmt.Printf("Listening for incoming connections on port %d...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go func(c net.Conn) {
			if err := handleConnection(c, expectedPassword); err != nil {
				fmt.Fprintf(c, "Error: %v\n", err)
			}
		}(conn)
	}
}

func handleConnection(conn net.Conn, expectedPassword string) error {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Read and verify password
	passwordHash, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading password: %v", err)
	}
	passwordHash = passwordHash[:len(passwordHash)-1] // Remove newline character

	if passwordHash != expectedPassword {
		return fmt.Errorf("password verification failed")
	}

	// Process the actual message
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			if err.Error() != "EOF" {
				return fmt.Errorf("error reading from connection: %v", err)
			}
			return nil
		}
		fmt.Printf("Received: %s", message)
	}
}

func sendToIP(ipAddr string, message string, password string, port int) {
	dialer := &net.Dialer{Timeout: 50 * time.Second}
	conn, err := dialer.Dial("tcp", ipAddr+":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("Error connecting to %s:%d: %v", ipAddr, port, err)
	}
	defer conn.Close()

	// Send password hash
	passwordHash := hashPassword(password)
	_, err = conn.Write([]byte(passwordHash + "\n"))
	if err != nil {
		log.Fatalf("Error sending password hash: %v", err)
	}

	// Send message
	_, err = conn.Write([]byte(message + "\n"))
	if err != nil {
		log.Fatalf("Error sending data: %v", err)
	}

	// Set a read deadline for receiving a response
	conn.SetReadDeadline(time.Now().Add(50 * time.Second))

	// Read response from the server
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Fatalf("Timeout waiting for server response: %v", err)
		} else {
			log.Fatalf("Error reading response: %v", err)
		}
	}
	if response != "" {
		fmt.Printf("Server response: %s", response)
	}
}

func hashPassword(password string) string {
	hash := sha512.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}
