# Go PowerShell

A Go library for interacting with PowerShell on Windows, Linux, and macOS.

## Features

- Execute PowerShell commands from Go
- Create remote PowerShell sessions
- Support for credentials and authentication
- Context support for timeouts and cancellation
- Cross-platform (Windows, Linux, macOS)

## Requirements

- Go 1.20 or higher
- PowerShell (Windows PowerShell or PowerShell Core)

## Installation

```bash
go get github.com/simonjanss/go-powershell
```

## Usage

### Basic Usage

```go
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
```

### Using Context for Timeouts

```go
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
}
```

### Remote Sessions

```go
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

	// Create a new remote session
	session, err := ps.NewSession("remote-server",
		powershell.WithUsernamePassword("username", "password"),
		powershell.WithSSL(),
	)
	if err != nil {
		log.Fatalf("Error creating session: %v", err)
	}
	defer session.Close()

	// Execute a command in the remote session
	output, err := session.Execute("Get-ComputerInfo")
	if err != nil {
		log.Fatalf("Error executing command: %v", err)
	}

	fmt.Println(string(output))
}
```

## Available Options

When creating a new session, you can use the following options:

- `WithUsernamePassword(username, password)` - Set username and password for authentication
- `UseHostName()` - Use hostname instead of computer name
- `WithAllowRedirection()` - Allow redirection
- `WithCertificateThumbprint(thumbprint)` - Set certificate thumbprint
- `WithSSL()` - Use SSL
- `WithAuthentication(auth)` - Set authentication type (Default, Basic, CredSSP, Digest, Kerberos, Negotiate, NegotiateWithImplicitCredential)
- `WithPort(port)` - Set port
- `WithNetworkAccess()` - Enable network access

## License

MIT License - see LICENSE file for details.