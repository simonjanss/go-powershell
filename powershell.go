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
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
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

// Cmd holds information for creating
// a command to be run in powershell
type Cmd struct {
	// command is the input from
	// the user creating the command
	command string

	// outBoundary is a token used to know
	// when to stop reading  from the stdout-pipe
	outBoundary string

	// errBoundary is a token used to know
	// when to stop reading  from the stderr-pipe
	errBoundary string

	// stdin is used to write the commands
	// to the underlying powershell-process
	stdin io.WriteCloser

	// stdout is the pipe for the underlying -
	// powershell-process standard output
	stdout io.ReadCloser

	// stderr is the pipe for the underlying -
	// powershell-process standard error
	stderr io.ReadCloser
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
		stdin:       s.stdin,
		stdout:      s.stdout,
		stderr:      s.stderr,
	}
}

// Execute a specified command in the shell
func (s *Shell) Execute(cmd string) ([]byte, error) {
	return s.command(cmd).withOutput()
}

// CreateCredential creates a automation credential with username and secret-var
func (s *Shell) CreateCredential(user, secret string) (string, error) {
	credential := "goCred" + createRandomString(8)
	cmd := fmt.Sprintf("$%s = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList %s, $%s",
		credential,
		user,
		secret,
	)
	err := s.command(cmd).Start()
	return credential, errors.Wrap(err, "powershell: ")
}

// ConvertToSecureString converts a secret to a secure-string
// will return the powershell variable for the secure-string or error
func (s *Shell) ConvertToSecureString(secret string) (string, error) {
	secure := "goPass" + createRandomString(8)
	err := s.command(fmt.Sprintf("$%s = ConvertTo-SecureString -String '%s' -AsPlainText -Force", secure, secret)).Start()
	return secure, errors.Wrap(err, "powershell: ")
}

// Output executes a command with output
func (c *Cmd) Output() ([]byte, error) {
	return c.withOutput()
}

// Run executes a command and wait for it to finish
func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

// Start the command
func (c *Cmd) Start() error {
	// wrap the command in special markers so we know when to stop reading from the pipes
	command := fmt.Sprintf("%s; echo '%s'; [Console]::Error.WriteLine('%s')\r\n", c.command, c.outBoundary, c.errBoundary)
	if _, err := c.stdin.Write([]byte(command)); err != nil {
		return errors.Wrap(errors.Wrap(err, c.command), "powershell: cannot execute command")
	}
	return nil
}

// Wait for command to finish
func (c *Cmd) Wait() error {
	// read stderr
	stderr := ""

	waiter := &sync.WaitGroup{}
	waiter.Add(1)
	go streamReader(c.stderr, c.errBoundary, &stderr, waiter)
	waiter.Wait()

	if len(stderr) > 0 {
		return errors.Wrap(errors.Wrap(errors.New(stderr), c.command), "powershell: ")
	}
	return nil
}

// withOutput reads and returns the stdout and stderr
func (c *Cmd) withOutput() ([]byte, error) {
	// read stdout and stderr
	stdout := ""
	stderr := ""

	waiter := &sync.WaitGroup{}
	waiter.Add(2)
	go streamReader(c.stdout, c.outBoundary, &stdout, waiter)
	go streamReader(c.stderr, c.errBoundary, &stderr, waiter)
	waiter.Wait()

	if len(stderr) > 0 {
		return nil, errors.Wrap(errors.Wrap(errors.New(stderr), c.command), "powershell: ")
	}
	return []byte(stdout), nil
}

// Session is a remote-session
type Session struct {
	sessionID string
	shell     *Shell
}

// NewSession creates a new session
func (s *Shell) NewSession(host string, opts ...Option) (*Session, error) {
	var settings internal.Settings
	settings.ComputerName = host
	for _, o := range opts {
		o.Apply(&settings)
	}

	if err := settings.Validate(); err != nil {
		return nil, err
	}

	return s.newSession(settings)
}

// newSession creates a new session
func (s *Shell) newSession(settings internal.Settings) (*Session, error) {
	args := settings.ToArgs()
	if settings.Username != "" && settings.Password != "" {
		secret, err := s.ConvertToSecureString(settings.Password)
		if err != nil {
			return nil, err
		}
		cred, err := s.CreateCredential(settings.Username, secret)
		if err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("-Credential $%s", cred))
	}

	sessionID := "goSess" + createRandomString(8)
	cmd := s.command(fmt.Sprintf("$%s = New-PSSession %s", sessionID, strings.Join(args, " ")))
	if err := cmd.Run(); err != nil {
		return nil, errors.Wrap(err, "powershell: Could not create new PSSession")
	}

	return &Session{sessionID, s}, nil
}

func createBoundary() string {
	return "$go" + createRandomString(12) + "$"
}

func createRandomString(bytes int) string {
	c := bytes
	b := make([]byte, c)

	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}

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
