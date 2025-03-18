package main

import (
	"fmt"
	"log"

	"github.com/simonjanss/go-powershell"
)

func main() {
	// Create a new PowerShell process
	ps, err := powershell.New()
	if err != nil {
		log.Fatalf("Error creating PowerShell process: %v", err)
	}
	defer ps.Close()

	// Execute a command
	output, err := ps.Execute("Get-Process | Select-Object -First 5")
	if err != nil {
		log.Fatalf("Error executing command: %v", err)
	}

	fmt.Println(string(output))
}