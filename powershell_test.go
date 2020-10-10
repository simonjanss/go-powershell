package powershell_test

import (
	"fmt"
	"testing"

	"github.com/matryer/is"
	"github.com/simonjanss/go-powershell"
)

func TestNew(t *testing.T) {
	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()
	fmt.Println(ps.GetPid())
}

func TestExecute(t *testing.T) {
	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()

	pwd, err := ps.Execute("dir")
	is.NoErr(err)
	fmt.Println(string(pwd))
}

func TestConcurrent(t *testing.T) {
	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()

	go func() {
		dir, err := ps.Execute("dir")
		is.Equal(err.Error(), "powershell: cannot execute command - powershell is busy")
		fmt.Println(string(dir))
	}()

	hello, err := ps.Execute("echo hello")
	is.NoErr(err)
	fmt.Println(string(hello))
}
