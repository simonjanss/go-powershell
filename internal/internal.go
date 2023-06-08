package internal

import (
	"errors"
	"strconv"
	"strings"
)

type Settings struct {
	ComputerName          string
	Username              string
	Password              string
	Credential            string
	UseHostName           bool
	AllowRedirection      bool
	Authentication        string
	CertificateThumbprint string
	Port                  int
	UseSSL                bool
	NetworkAccess         bool
}

func (s *Settings) Validate() error {
	var auth = map[string]bool{
		"default":                         true,
		"basic":                           true,
		"credssp":                         true,
		"digest":                          true,
		"kerberos":                        true,
		"negotiate":                       true,
		"negotiatewithimplicitcredential": true,
	}
	if !auth[strings.ToLower(s.Authentication)] && s.Authentication != "" {
		return errors.New("Need to specify a valid authentication-type for powershell")
	}
	return nil
}

func (s *Settings) ToArgs() []string {
	args := make([]string, 0)

	if s.ComputerName != "" {
		if s.UseHostName {
			args = append(args, "-HostName")
		} else {
			args = append(args, "-ComputerName")
		}
		args = append(args, quoteArg(s.ComputerName))
	}

	if s.Username != "" {
		args = append(args, "-Username")
		args = append(args, quoteArg(s.Username))
	}

	if s.AllowRedirection {
		args = append(args, "-AllowRedirection")
	}

	if s.Authentication != "" {
		args = append(args, "-Authentication")
		args = append(args, quoteArg(s.Authentication))
	}

	if s.CertificateThumbprint != "" {
		args = append(args, "-CertificateThumbprint")
		args = append(args, quoteArg(s.CertificateThumbprint))
	}

	if s.Port > 0 {
		args = append(args, "-Port")
		args = append(args, strconv.Itoa(s.Port))
	}

	if s.Credential != "" {
		args = append(args, "-Credential")
		args = append(args, s.Credential) // do not quote, as it contains a variable name when using password auth
	}

	if s.UseSSL {
		args = append(args, "-UseSSL")
	}

	if s.NetworkAccess {
		args = append(args, "-EnableNetworkAccess")
	}

	return args
}

func quoteArg(s string) string {
	return "'" + strings.Replace(s, "'", "\"", -1) + "'"
}
