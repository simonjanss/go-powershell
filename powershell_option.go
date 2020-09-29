package powershell

import "github.com/simonjanss/go-powershell/internal"

type Option interface {
	Apply(*internal.Settings)
}

type withUsernamePassword struct {
	username string
	password string
}

func WithUsernamePassword(username, password string) Option {
	return withUsernamePassword{username, password}
}

func (w withUsernamePassword) Apply(o *internal.Settings) {
	o.Username = w.username
	o.Password = w.password
}

type withAllowRedirection bool

func WithAllowRedirection() Option {
	return withAllowRedirection(true)
}

func (w withAllowRedirection) Apply(o *internal.Settings) { 
	o.AllowRedirection = bool(w) 
}

type withCertificateThumbprint string

func WithCertificateThumbprint(thumbprint string) Option {
	return withCertificateThumbprint(thumbprint)
}

func (w withCertificateThumbprint) Apply(o *internal.Settings) { 
	o.CertificateThumbprint = string(w)
}

type withSSL bool

func WithSSL() Option {
	return withSSL(true)
}

func (w withSSL) Apply(o *internal.Settings) { 
	o.UseSSL = bool(w) 
}

type withAuthentication string

func WithAuthentication(auth string) Option {
	return withAuthentication(auth)
}

func (w withAuthentication) Apply(o *internal.Settings) { 
	o.Authentication = string(w)
}

type withPort int

func WithPort(port int) Option {
	return withPort(port)
}

func (w withPort) Apply(o *internal.Settings) { 
	o.Port = int(w)
}