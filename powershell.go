package powershell

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/pkg/errors"

	"github.com/simonjanss/go-powershell/internal"
)

// Shell holds the underlying powershell-process
// and pipes for stdin, stdout and stderr
type Shell struct {
	// cmd is the underlying powershell-process
	cmd *exec.Cmd

	// stdin is used to write the commands
	// to the underlying powershell-process
	stdin io.WriteCloser

	// stdout is the pipe for the underlying -
	// powershell-process standard output
	stdout io.ReadCloser

	// stderr is the pipe for the underlying -
	// powershell-process standard error
	stderr io.ReadCloser

	// busy is set to true if
	// the shell is running a command
	busy bool
}

// New creates a new powershell-process
func New() (*Shell, error) {
	// specify which binary to use
	// depending on os
	var binary string
	switch os := runtime.GOOS; os {
	case "darwin", "linux":
		binary = "pwsh"
	case "windows":
		binary = "powershell.exe"
	default:
		return nil, errors.Errorf("powershell: GOOS %s not supported", runtime.GOOS)
	}

	cmd := exec.Command(binary, "-NoExit", "-Command", "-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.Wrap(err, "powershell: cannot get stdin-pipe")
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.Wrap(err, "powershell: cannot get stdout-pipe")
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, errors.Wrap(err, "powershell: cannot get stderr-pipe")
	}

	if err := cmd.Start(); err != nil {
		return nil, errors.Wrap(err, "powershell: cannot start cmd")
	}

	return &Shell{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
	}, nil
}

// Close closes the underlying powershell-process
func (s *Shell) Close() error {
	if s == nil || s.cmd == nil {
		return errors.New("powershell: cannot close nil-pointer")
	}

	// kill the underlying powershell-process
	if s.cmd.Process != nil {
		if err := s.cmd.Process.Kill(); err != nil {
			return errors.Wrap(err, "powershell: cannot kill underlying process")
		}
	}

	s.cmd = nil
	s.stdin = nil
	s.stdout = nil
	s.stderr = nil
	return nil
}

// GetPid returns the process id for the powershell-process
func (s *Shell) GetPid() int { return s.cmd.Process.Pid }

// Execute a specified command in the shell
func (s *Shell) Execute(cmd string) ([]byte, error) {
	return s.command(cmd).execute()
}

// createCredential creates a automation credential with username and secret-var
func (s *Shell) createCredential(user, password string) (*Credential, error) {
	// Create a secure string from the password
	secret := "goPass" + createRandomString(8)
	cmd := s.command(fmt.Sprintf("$%s = ConvertTo-SecureString -String '%s' -AsPlainText -Force", secret, password))
	if _, err := cmd.execute(); err != nil {
		return nil, errors.Wrap(err, "powershell: failed to create secure string for credential")
	}

	// Create the credential with the secure string
	id := "goCred" + createRandomString(8)
	credCmd := fmt.Sprintf("$%s = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList %s, $%s",
		id,
		user,
		secret,
	)

	if _, err := s.command(credCmd).execute(); err != nil {
		return nil, errors.Wrap(err, "powershell: failed to create credential")
	}

	return &Credential{id, user}, nil
}

// Cmd holds information for creating
// a command to be run in powershell
type Cmd struct {
	// command is the input from
	// the user creating the command
	command string

	// Credential to use with the command
	credential *Credential

	// outBoundary is a token used to know
	// when to stop reading  from the stdout-pipe
	outBoundary string

	// errBoundary is a token used to know
	// when to stop reading  from the stderr-pipe
	errBoundary string

	// shell is the underlying powershell-process
	shell *Shell
}

// Command creates a command from the user-input
func (s *Shell) Command(cmd string) *Cmd {
	return s.command(cmd)
}

// command creates a command
func (s *Shell) command(cmd string) *Cmd {
	return &Cmd{
		command:     cmd,
		outBoundary: createBoundary(),
		errBoundary: createBoundary(),
		shell:       s,
	}
}

// execute the command - will return output or error
func (c *Cmd) execute() ([]byte, error) {
	// check if the shell is busy
	if c.shell.busy {
		return nil, errors.New("powershell: cannot execute command - powershell is busy")
	}
	// set the shell to busy and start the command
	c.shell.busy = true

	// wrap the command in special markers so we know when to stop reading from the pipes
	command := fmt.Sprintf("%s; echo '%s'; [Console]::Error.WriteLine('%s')\r\n", c.command, c.outBoundary, c.errBoundary)
	if _, err := c.shell.stdin.Write([]byte(command)); err != nil {
		return nil, errors.Wrap(errors.Wrap(err, c.command), "powershell: cannot execute command")
	}

	// read stdout and stderr
	stdout := ""
	stderr := ""

	waiter := &sync.WaitGroup{}
	waiter.Add(2)
	go streamReader(c.shell.stdout, c.outBoundary, &stdout, waiter)
	go streamReader(c.shell.stderr, c.errBoundary, &stderr, waiter)
	waiter.Wait()

	// The command has finished
	// set busy to false
	c.shell.busy = false

	// check for errors in stderr
	if len(stderr) > 0 {
		return nil, errors.Wrap(errors.Wrap(errors.New(stderr), c.command), "powershell: ")
	}

	return []byte(stdout), nil
}

// withSession wraps the command to be run
// within the specified session
func (c *Cmd) withSession(id string) {
	c.command = fmt.Sprintf("Invoke-Command -Session $%s -ScriptBlock {%s}", id, c.command)
	if c.credential != nil {
		c.command = fmt.Sprintf("%s -Credential $%s", c.command, c.credential.id)
	}
}

// Session is a remote-session
type Session struct {
	// id of the session
	id string

	// shell is the underlying
	// powershell-process
	shell *Shell

	// credential to use for
	// running commands in the session
	credential *Credential
}

// NewSession creates a new session
func (s *Shell) NewSession(host string, opts ...Option) (*Session, error) {
	// set the computername to the settings
	var settings internal.Settings
	settings.ComputerName = host

	// Apply the options to the settings
	for _, o := range opts {
		o.Apply(&settings)
	}

	// Validate the settings
	if err := settings.Validate(); err != nil {
		return nil, err
	}

	// create a new session with the settings
	return s.newSession(settings)
}

// newSession creates a new session
func (s *Shell) newSession(settings internal.Settings) (*Session, error) {
	// Create arguments from the settings
	args := settings.ToArgs()

	// Create a credential if username and password is provided
	var cred *Credential
	if settings.Username != "" && settings.Password != "" {
		cred, err := s.createCredential(settings.Username, settings.Password)
		if err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("-Credential $%s", cred.id))
	}

	// Create a id for the session
	sessionID := "goSess" + createRandomString(8)

	// Create the new session with the ID and arguments
	cmd := s.command(fmt.Sprintf("$%s = New-PSSession %s", sessionID, strings.Join(args, " ")))
	if _, err := cmd.execute(); err != nil {
		return nil, errors.Wrap(err, "powershell: Could not create new PSSession")
	}

	return &Session{id: sessionID, shell: s, credential: cred}, nil
}

// SetCredential sets a specific credential which
// will be used to run commands within the session
func (s *Session) SetCredential(cred *Credential) {
	s.credential = cred
}

// Execute a command in the current session
func (s *Session) Execute(cmd string) ([]byte, error) {
	command := s.shell.command(cmd)
	command.withSession(s.id)
	return command.execute()
}

// Close will disconnect from the powershell-session
func (s *Session) Close() error {
	if _, err := s.Execute(fmt.Sprintf("Disconnect-PSSession -Session $%s", s.id)); err != nil {
		return errors.Wrap(err, "powershell: failed to disconnect from ps-session")
	}

	s.shell = nil
	s.credential = nil
	return nil
}

// GetPid returns the process id of the sessions powershell-process
func (s *Session) GetPid() int { return s.shell.cmd.Process.Pid }

// Credential holds the id and username
// for a PSCredential
type Credential struct {
	id       string
	username string
}

// ID of the credential
func (c *Credential) ID() string {
	return c.id
}

// Username of the credential
func (c *Credential) Username() string {
	return c.username
}

// createBoundary creates a boundary that will
// be used to determine when to stop running a cmd
func createBoundary() string {
	return "$go" + createRandomString(12) + "$"
}

// createRandomString creates a random string
// with the specified bytes, is used for creating
// ids and such
func createRandomString(bytes int) string {
	c := bytes
	b := make([]byte, c)

	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}

// streamReader reads the stdout and stderr from a command
func streamReader(stream io.Reader, boundary string, buffer *string, signal *sync.WaitGroup) error {
	// read all output until we have found our boundary token
	output := ""
	bufsize := 64
	marker := boundary + "\r\n"

	for {
		buf := make([]byte, bufsize)
		read, err := stream.Read(buf)
		if err != nil {
			return err
		}

		output = output + string(buf[:read])

		if strings.HasSuffix(output, marker) {
			break
		}
	}

	*buffer = strings.TrimSuffix(output, marker)
	signal.Done()
	return nil
}
