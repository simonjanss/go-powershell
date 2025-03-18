package powershell_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/simonjanss/go-powershell"
)

var (
	server   = os.Getenv("TEST_SERVER")
	user     = os.Getenv("TEST_USER")
	password = os.Getenv("TEST_PASSWORD")
)

func TestNew(t *testing.T) {
	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()
	fmt.Println(ps.GetPid())
}

func TestNewWithContext(t *testing.T) {
	is := is.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ps, err := powershell.NewWithContext(ctx)
	is.NoErr(err)
	defer ps.Close()
	
	pid := ps.GetPid()
	is.True(pid > 0)
}

func TestExecute(t *testing.T) {
	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)

	var tt = []struct {
		name       string
		command    string
		shouldFail bool
		hasOutput  bool
	}{
		{name: "dir-command", command: "dir", shouldFail: false, hasOutput: true},
		{name: "cd-command", command: "cd ..", shouldFail: false, hasOutput: false},
		{name: "random-command", command: "this-should-fail", shouldFail: true, hasOutput: false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			output, err := ps.Execute(tc.command)
			if !tc.shouldFail {
				is.NoErr(err)
			}
			if tc.hasOutput {
				is.True(output != nil)
			} else {
				is.True(output == nil)
			}
		})
	}

	err = ps.Close()
	is.NoErr(err)
}

func TestExecuteWithContext(t *testing.T) {
	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()

	// Test with sufficient timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	output, err := ps.ExecuteWithContext(ctx, "echo 'context test'")
	is.NoErr(err)
	is.Equal(string(output), "context test")

	// Test with timeout that should trigger
	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()

	_, err = ps.ExecuteWithContext(ctx2, "Start-Sleep -Seconds 2; echo 'should not reach here'")
	is.True(err != nil) // Should get timeout error
}

func TestConcurrentExecute(t *testing.T) {
	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()

	// Create a channel to capture the error from the goroutine
	errChan := make(chan error, 1)

	go func() {
		_, err := ps.Execute("dir")
		errChan <- err
	}()

	// Give the goroutine time to start
	time.Sleep(100 * time.Millisecond)

	// This should fail because the shell is busy
	_, err = ps.Execute("echo hello")
	is.True(err != nil)
	is.True(err.Error() == "powershell: cannot execute command - powershell is busy")

	// Wait for the first command to complete
	err = <-errChan
	is.NoErr(err)

	// Now the shell should be available again
	output, err := ps.Execute("echo hello")
	is.NoErr(err)
	is.Equal(string(output), "hello")
}

func TestSession(t *testing.T) {
	// Skip if no server credentials are provided
	if server == "" || user == "" || password == "" {
		t.Skip("Skipping remote session tests - no server credentials provided")
	}

	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()

	var tt = []struct {
		name     string
		user     string
		password string
		auth     string
	}{
		{name: "auth-default", user: user, password: password, auth: "Default"},
		{name: "auth-credssp", user: user, password: password, auth: "CredSSP"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			session, err := ps.NewSession(server,
				powershell.WithUsernamePassword(user, password),
				powershell.WithAuthentication(tc.auth),
			)
			is.NoErr(err)
			defer session.Close()

			is.Equal(session.GetPid(), ps.GetPid())
			output, err := session.Execute("echo hello")
			is.NoErr(err)
			is.Equal("hello", string(output))
		})
	}
}

func TestSessionWithContext(t *testing.T) {
	// Skip if no server credentials are provided
	if server == "" || user == "" || password == "" {
		t.Skip("Skipping remote session tests - no server credentials provided")
	}

	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session, err := ps.NewSessionWithContext(ctx, server,
		powershell.WithUsernamePassword(user, password),
		powershell.WithAuthentication("Default"),
	)
	is.NoErr(err)
	defer session.Close()

	// Test execution with context
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	output, err := session.ExecuteWithContext(ctx2, "echo 'context session test'")
	is.NoErr(err)
	is.Equal("context session test", string(output))
}

func TestCloseNilShell(t *testing.T) {
	is := is.New(t)

	var ps *powershell.Shell
	err := ps.Close()
	is.True(err != nil)
	is.Equal("powershell: cannot close nil-pointer", err.Error())
}

func TestGetPidAfterClose(t *testing.T) {
	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	
	pid := ps.GetPid()
	is.True(pid > 0)
	
	err = ps.Close()
	is.NoErr(err)
	
	pid = ps.GetPid()
	is.Equal(-1, pid) // Should return -1 after close
}

func TestSessionGetPidAfterClose(t *testing.T) {
	// Skip if no server credentials are provided
	if server == "" || user == "" || password == "" {
		t.Skip("Skipping remote session tests - no server credentials provided")
	}

	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()

	session, err := ps.NewSession(server,
		powershell.WithUsernamePassword(user, password),
	)
	is.NoErr(err)
	
	pid := session.GetPid()
	is.True(pid > 0)
	
	err = session.Close()
	is.NoErr(err)
	
	pid = session.GetPid()
	is.Equal(-1, pid) // Should return -1 after close
}