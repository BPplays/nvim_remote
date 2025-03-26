package main

import (
	"bufio"
	"crypto/sha512"
	"crypto/subtle"
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
	clipboard "github.com/dece2183/go-clipboard"

	"github.com/gin-gonic/gin"
	"net/http"
)

type ime_req struct {
	IME string    `json:"IME" binding:"required"`
	IME_value string    `json:"IME_value" binding:"required"`
}

type clip_req struct {
	Put string    `json:"Put" binding:"required"`
}

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
var debug bool


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
	pflag.BoolVarP(&debug, "debug", "e", false, "Receive UTF-8 string over TCP")
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



func ret_im() (im_name string, im_value string) {
	im_cmd := ""
	im_m_name := ""
	var im_mode []string
	switch cos {
	case Windows:
		im_cmd = "im-select.exe"
		im_m_name = "im-select"

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
		return "", ""
	}

	// Print the output
	fmt.Printf("%v output: %s\n", im_cmd, output)

	return im_m_name, string(output)
}



func startServer(expectedPassword string, port int) {
	r := gin.Default()

	authMiddleware := gin.BasicAuth(gin.Accounts{
		"user": "password", // Replace with your credentials
	})

	r.GET("/current_ime", authMiddleware, func(c *gin.Context) {
		im_name, im_value := ret_im()
		response := ime_req{
			IME:       im_name,
			IME_value: im_value,
		}

		c.JSON(http.StatusOK, response)
	})



	r.POST("/current_ime", authMiddleware, func(c *gin.Context) {
		var reqData ime_req

		if err := c.ShouldBindJSON(&reqData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		im_map[reqData.IME] = reqData.IME_value
		fmt.Println(im_map)
		switch_im()

		c.JSON(http.StatusOK, gin.H{"message": "got_ime"})
	})

	r.POST("/clipboard_set", authMiddleware, func(c *gin.Context) {
		var reqData clip_req

		if err := c.ShouldBindJSON(&reqData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		set_clipboard(reqData.Put)

		c.JSON(http.StatusOK, gin.H{"message": "got_clip"})
	})

	r.Run(fmt.Sprintf("[::]:%v", port), fmt.Sprintf("0.0.0.0:%v", port))
}

func set_clipboard(str string) {
	c := clipboard.New(clipboard.ClipboardOptions{})

	if err := c.CopyText(str); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}


// const get_im_str string = "mode:getim"
// const set_im_str string = "set_modes"



// func handleConnection(conn net.Conn, expectedPassword string) error {
// 	var get_im bool = false
// 	defer conn.Close()
// 	reader := bufio.NewReader(conn)
//
// 	// Read and verify password
// 	log.Println("Waiting to read password...")
// 	passwordHash, err := readUntilNull(reader)
// 	if err != nil {
// 		return fmt.Errorf("error reading password: %v\n", err)
// 	}
//
//
// 	log.Printf("Received password hash: %s\n", passwordHash)
// 	if secCompareStrings(passwordHash, expectedPassword) != true {
// 		fmt.Printf("expected pass: %v\n", expectedPassword)
// 		return fmt.Errorf("password verification failed")
// 	}
//
// 	// Process the actual message
// 	for {
// 		log.Println("Waiting to read message...")
// 		conn.Write(str2nulbs(send_pass_str))
// 		message, err := readUntilNull(reader)
// 		if err != nil {
// 			if err.Error() != "EOF" {
// 				return fmt.Errorf("error reading from connection: %v", err)
// 			}
// 			return nil
// 		}
// 		response := "Message processed successfully\n"
//
// 		log.Printf("Received message: %s", message)
// 		if message == get_im_str {
// 			get_im = true
// 		}
// 		spl_msg := strings.Split(message, ":")
// 		if get_im {
// 			response = ret_im()
// 		} else if spl_msg[0] == set_im_str {
// 			parse_im(&spl_msg[1])
// 			fmt.Println(im_map)
// 			switch_im()
// 		}
//
// 		// // Send response back to client
// 		// _, err = conn.Write(str2nulbs(send_msg_str))
// 		// if err != nil {
// 		// 	log.Println(err)
// 		// }
//
// 		_, err = conn.Write(str2nulbs(response))
// 		if err != nil {
// 			return fmt.Errorf("error sending response: %v", err)
// 		}
// 	}
// }



func readUntilNull(reader *bufio.Reader) (string, error) {
	var result strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == null_b {
			break
		}
		result.WriteByte(b)
	}
	return result.String(), nil
}


const null_b byte = '\u0000'
var null_bsl []byte = []byte{0}


func str2nulbs(s string) []byte {
	b := []byte(s)
	b = append(b, null_b)
	return b
}



const send_pass_str string = "com:sendpass"
const send_msg_str string = "com:sendmsg"


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
	if debug {
		fmt.Println("sending pass")
	}
	_, err = conn.Write(str2nulbs(passwordHash))
	if err != nil {
		log.Fatalf("Error sending password hash: %v", err)
	}

	// Set a read deadline for receiving the 'send_pass_str' from the server
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	// Read response from the server and wait for 'send_pass_str'
	if debug {
		fmt.Println("waiting for 'send_pass_str'")
	}
	bufReader := bufio.NewReader(conn)
	response, err := readUntilNull(bufReader)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Fatalf("Timeout waiting for server response: %v", err)
		} else {
			log.Fatalf("Error reading response: %v", err)
		}
	}
	if response != send_pass_str {
		log.Fatalf("Unexpected server response: %s", response)
	}









	// Send message
	if debug {
		fmt.Println("sending msg")
	}
	_, err = conn.Write(str2nulbs(message))
	if err != nil {
		log.Fatalf("Error sending data: %v", err)
	}





	// // Set a read deadline for receiving the 'send_pass_str' from the server
	// conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
	//
	// // Read response from the server and wait for 'send_pass_str'
	// if debug {
	// 	fmt.Println("waiting for 'send_msg_str'")
	// }
	// bufReader = bufio.NewReader(conn)
	// response, err = readUntilNull(bufReader)
	// if err != nil {
	// 	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
	// 		log.Fatalf("Timeout waiting for server response: %v", err)
	// 	} else {
	// 		log.Fatalf("Error reading response: %v", err)
	// 	}
	// }
	// if response != send_msg_str {
	// 	log.Fatalf("Unexpected server response: %s", response)
	// }







	// Set a read deadline for receiving a response
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	// Read response from the server
	if debug {
		fmt.Println("recv resp")
	}
	response, err = bufio.NewReader(conn).ReadString(null_b)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Fatalf("Timeout waiting for server response: %v", err)
		} else {
			log.Fatalf("Error reading response: %v", err)
		}
	}
	if debug {
		fmt.Printf("Server response: %s", response)
	}

	if get_im {
		fmt.Print(response)
	}
}

func hashPassword(password string) string {
	hash := sha512.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}



// CompareStrings securely compares two strings using constant-time comparison
func secCompareStrings(str1, str2 string) bool {
	// Convert strings to byte slices
	bytes1 := []byte(str1)
	bytes2 := []byte(str2)

	// Use constant-time comparison
	return subtle.ConstantTimeCompare(bytes1, bytes2) == 1
}


