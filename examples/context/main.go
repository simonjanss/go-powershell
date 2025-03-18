package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/simonjanss/go-powershell"
)

func main() {
	// Create a new PowerShell process
	ps, err := powershell.New()
	if err != nil {
		log.Fatalf("Error creating PowerShell process: %v", err)
	}
	defer ps.Close()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Execute a command with context
	output, err := ps.ExecuteWithContext(ctx, "Start-Sleep -Seconds 2; Get-Date")
	if err != nil {
		log.Fatalf("Error executing command: %v", err)
	}

	fmt.Println(string(output))

	// Try with a timeout that will trigger
	ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel2()

	_, err = ps.ExecuteWithContext(ctx2, "Start-Sleep -Seconds 3; Get-Date")
	if err != nil {
		fmt.Printf("Expected timeout error: %v\\n", err)
	}
}