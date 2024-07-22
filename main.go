package main

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

// OS represents the operating system type.
type OS int

// Define constants for each operating system.
const (
	Windows OS = iota
	MacOS
	Linux
)

func (os OS) String() string {
	switch os {
	case Windows:
		return "Windows"
	case MacOS:
		return "MacOS"
	case Linux:
		return "Linux"
	default:
		return "Unknown"
	}
}


func getCurrentOS() OS {
	switch runtime.GOOS {
	case "windows":
		return Windows
	case "darwin":
		return MacOS
	case "linux":
		return Linux
	default:
		return -1
	}
}

var cos OS = getCurrentOS()


var timeout int
var get_im bool


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
	pflag.IntVarP(&timeout, "timeout", "t", 3000, "timeout in ms")

	pflag.Parse()


	hash_pass := hashPassword(password)

	if isServer {
		startServer(hash_pass, port)
	} else if ipAddr != "" {
		if im_message == "" {
			get_im = true
			im_message = get_im_str
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

// checkCommandExists checks if a command exists by trying to execute it.
func checkCommandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// checkInputMethodFramework checks if fcitx5-remote, fcitx-remote, or ibus is installed.
func get_lin_im() string {
	if checkCommandExists("fcitx5-remote") {
		return "fcitx5-remote"
	} else if checkCommandExists("fcitx-remote") {
		return "fcitx-remote"
	} else if checkCommandExists("ibus") {
		return "ibus"
	}
	return "none"
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

func isIPv6(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() == nil
}

func FormatIPv6(ip string) (string, error) {
	// Parse the IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP address")
	}

	// Check if it's an IPv6 address
	if parsedIP.To4() == nil {
		// It's an IPv6 address, format it with brackets
		return fmt.Sprintf("[%s]", ip), nil
	}

	// Not an IPv6 address
	return "", fmt.Errorf("the IP address is not IPv6")
}


func switch_im() {
	im_cmd := ""
	var im_mode []string
	switch cos {
	case Windows:
		im_cmd = "im-select.exe"
		im_mode = append(im_mode, im_map["im-select"])

	case Linux:
		switch get_lin_im() {
		case "fcitx5-remote":
			im_cmd = "fcitx5-remote"
			im_mode = append(im_mode, "-o")
			im_mode = append(im_mode, im_map["fcitx5-remote"])

		case "fcitx-remote":
			log.Fatalln("fcitx-remote unsupported")

		case "ibus":
			log.Fatalln("ibus unsupported")
		}

	case MacOS:
		log.Fatalln("MacOS is unsupported")
	}

	cmd := exec.Command(im_cmd, im_mode...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error executing command: %s\n", err)
		return
	}

	// Print the output
	fmt.Printf("%v output: %s\n", im_cmd, output)
}



func ret_im() string {
	im_cmd := ""
	var im_mode []string
	switch cos {
	case Windows:
		im_cmd = "im-select.exe"

	case Linux:
		switch get_lin_im() {
		case "fcitx5-remote":
			im_cmd = "fcitx5-remote"
			im_mode = append(im_mode, "-n")

		case "fcitx-remote":
			log.Fatalln("fcitx-remote unsupported")

		case "ibus":
			log.Fatalln("ibus unsupported")
		}

	case MacOS:
		log.Fatalln("MacOS is unsupported")
	}

	cmd := exec.Command(im_cmd, im_mode...)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error executing command: %s\n", err)
		return ""
	}

	// Print the output
	fmt.Printf("%v output: %s\n", im_cmd, output)
	return string(output)
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



const get_im_str string = "mode:getim"



func handleConnection(conn net.Conn, expectedPassword string) error {
	var get_im bool = false
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Read and verify password
	log.Println("Waiting to read password...")
	passwordHash, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading password: %v\n", err)
	}

	log.Printf("Received password hash: %s\n", passwordHash)
	if passwordHash != expectedPassword {
		fmt.Printf("expected pass: %v\n", expectedPassword)
		return fmt.Errorf("password verification failed")
	}

	// Process the actual message
	for {
		log.Println("Waiting to read message...")
		message, err := reader.ReadString('\n')
		if err != nil {
			if err.Error() != "EOF" {
				return fmt.Errorf("error reading from connection: %v", err)
			}
			return nil
		}
		response := "Message processed successfully\n"

		log.Printf("Received message: %s", message)
		if message == get_im_str {
			get_im = true
		}
		if get_im {
			response = ret_im()
		} else {
			parse_im(&message)
			fmt.Println(im_map)
			switch_im()
		}

		// Send response back to client
		_, err = conn.Write([]byte(response))
		if err != nil {
			return fmt.Errorf("error sending response: %v", err)
		}
	}
}

func sendToIP(ipAddr string, message string, password string, port int) {
	if isIPv6(ipAddr) {
		var err error
		ipAddr, err = FormatIPv6(ipAddr)
		if err != nil {
			log.Fatalln(err)
		}

	}
	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Millisecond}
	conn, err := dialer.Dial("tcp", ipAddr+":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("Error connecting to %s:%d: %v", ipAddr, port, err)
	}
	defer conn.Close()

	// Send password hash
	passwordHash := hashPassword(password)
	_, err = conn.Write([]byte(passwordHash))
	if err != nil {
		log.Fatalf("Error sending password hash: %v", err)
	}

	// Send message
	_, err = conn.Write([]byte(message))
	if err != nil {
		log.Fatalf("Error sending data: %v", err)
	}

	// Set a read deadline for receiving a response
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

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
