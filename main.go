package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	clipboard "github.com/dece2183/go-clipboard"
	"github.com/spf13/pflag"
	"golang.org/x/text/message"

	"net/http"

	"github.com/gin-gonic/gin"
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
	var endpoint string
	var password string
	var isServer bool
	var port int

	pflag.StringVarP(&ipAddr, "ip", "i", "", "IP address to send the UTF-8 string to")
	pflag.StringVarP(&im_message, "message", "m", "", "UTF-8 string to send")
	pflag.StringVarP(&endpoint, "endpoint", "n", "", "UTF-8 string to send")
	pflag.StringVarP(&password, "password", "p", "", "Password (hashed with SHA-512)")
	pflag.BoolVarP(&isServer, "receive", "d", false, "Receive UTF-8 string over TCP")
	pflag.BoolVarP(&debug, "debug", "e", false, "Receive UTF-8 string over TCP")
	pflag.IntVarP(&port, "port", "o", 32512, "Port number to use")
	pflag.IntVarP(&timeout, "timeout", "t", 3000, "timeout in ms")

	pflag.Parse()

	if !debug {
		gin.SetMode(gin.ReleaseMode)
	}


	// hash_pass := hashPassword(password)

	if isServer {
		startServer(password, port)
	} else if ipAddr != "" {
		if im_message == "" {
			get_im = true
			// im_message = get_im_str
			makeGetRequest()
		}
		if password == "" {
			fmt.Println("Please provide a password with -p.")
			os.Exit(1)
		}
		url := "http://localhost:32512/current_ime" // Your POST URL
		username := "admin"                        // Your username
		data := map[string]interface{}{
			"IME":       "value",
			"IME_value": im_message,
		}

		makePostRequest(url, username, password, data)

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

func makePostRequest(url string, username string, password string, data interface{}) {
	// Encode the data into JSON format
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new request with Basic Authentication
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal(err)
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/json")

	// Set Basic Authentication header
	req.SetBasicAuth(username, password)

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Read and print the response body
	body := make([]byte, resp.ContentLength)
	_, err = resp.Body.Read(body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Response Body:", string(body))
}


func makeGetRequest(url string) string {
	// Send a GET request
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Define a variable to hold the parsed JSON
	var response ime_req

	// Parse the JSON response into the Response struct
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Fatal(err)
	}

	// Return the IME_value from the response struct
	return response.IME_value
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

	formatted := string(output)
	formatted = strings.TrimSuffix(formatted, "\r\n") // Remove \r\n
	formatted = strings.TrimSuffix(formatted, "\n")   // Remove \n if it remains

	return im_m_name, formatted
}



func startServer(expectedPassword string, port int) {
	r := gin.Default()

	authMiddleware := gin.BasicAuth(gin.Accounts{
		"admin": expectedPassword, // Replace with your credentials
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

		parse_im(&reqData.IME_value)
		fmt.Println(im_map)
		switch_im()

		c.JSON(http.StatusOK, gin.H{"message": "set_ime"})
	})

	r.POST("/clipboard_set", authMiddleware, func(c *gin.Context) {
		var reqData clip_req

		if err := c.ShouldBindJSON(&reqData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		set_clipboard(reqData.Put)

		c.JSON(http.StatusOK, gin.H{"message": "set_clip"})
	})

	r.Run(fmt.Sprintf("[::]:%v", port))
}

func set_clipboard(str string) {
	c := clipboard.New(clipboard.ClipboardOptions{})

	if err := c.CopyText(str); err != nil {
		fmt.Println(err)
		os.Exit(1)
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


