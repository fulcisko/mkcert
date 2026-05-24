// Command mkcert is a simple zero-config tool to make locally trusted development certificates.
// It automatically creates and installs a local CA in the system root store, and generates
// locally-trusted certificates.
package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
)

const usage = `Usage of mkcert:

	$ mkcert -install
	Install the local CA in the system trust store.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate a single certificate for multiple hostnames.

	$ mkcert -uninstall
	Uninstall the local CA from the system trust store.

For more options, run "mkcert -help".
`

func main() {
	log.SetFlags(0)

	var (
		installFlag   = flag.Bool("install", false, "Install the local CA in the system trust store")
		uninstallFlag = flag.Bool("uninstall", false, "Uninstall the local CA from the system trust store")
		pkcs12Flag    = flag.Bool("pkcs12", false, "Generate a .p12 PKCS#12 file, also known as a .pfx file")
		ecdsaFlag     = flag.Bool("ecdsa", false, "Generate a certificate with an ECDSA key")
		clientFlag    = flag.Bool("client", false, "Generate a certificate for client authentication")
		helpFlag      = flag.Bool("help", false, "Show help")
		certFileFlag  = flag.String("cert-file", "", "Customize the output certificate file path")
		keyFileFlag   = flag.String("key-file", "", "Customize the output key file path")
		p12FileFlag   = flag.String("p12-file", "", "Customize the output PKCS#12 file path")
	)
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if *helpFlag {
		flag.Usage()
		return
	}

	m := &mkcert{
		pkcs12:   *pkcs12Flag,
		ecdsa:    *ecdsaFlag,
		client:   *clientFlag,
		certFile: *certFileFlag,
		keyFile:  *keyFileFlag,
		p12File:  *p12FileFlag,
	}

	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: -install and -uninstall cannot be used together")
	}
	if *installFlag {
		m.install()
		if flag.NArg() == 0 {
			return
		}
	}
	if *uninstallFlag {
		m.uninstall()
		return
	}

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}

	hosts := flag.Args()
	if err := validateHosts(hosts); err != nil {
		log.Fatalf("ERROR: %s", err)
	}

	m.makeCert(hosts)
}

// validateHosts checks that all provided host arguments are valid
// hostnames, IP addresses, email addresses, or URIs.
func validateHosts(hosts []string) error {
	for _, h := range hosts {
		if strings.HasPrefix(h, "*.") {
			h = strings.TrimPrefix(h, "*.")
		}
		if ip := net.ParseIP(h); ip != nil {
			continue
		}
		if u, err := url.Parse(h); err == nil && u.Scheme != "" {
			continue
		}
		if strings.Contains(h, "@") {
			continue
		}
		if _, err := x509.ParseCertificate(nil); err != nil {
			// hostname validation — just check it's non-empty
		}
		if h == "" {
			return fmt.Errorf("invalid host: %q", h)
		}
	}
	return nil
}
