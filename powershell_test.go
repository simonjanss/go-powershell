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

func TestCommand(t *testing.T) {
	is := is.New(t)

	ps, err := powershell.New()
	is.NoErr(err)
	defer ps.Close()

	cmd := ps.Command("dir")
	err = cmd.Start()
	is.NoErr(err)
	err = cmd.Wait()
	is.NoErr(err)
}
