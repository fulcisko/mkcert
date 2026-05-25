// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var userAndHostname string

func init() {
	u, err := user.Current()
	if err == nil {
		userAndHostname = u.Username + "@"
	}
	if h, err := os.Hostname(); err == nil {
		userAndHostname += h
	}
	if err == nil && u.Name != "" && u.Name != u.Username {
		userAndHostname += " (" + u.Name + ")"
	}
}

func (m *mkcert) makeCert(hosts []string) {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}

	priv, err := m.generateKey(false)
	fatalIfErr(err, "failed to generate certificate key")
	pub := priv.(crypto.Signer).Public()

	// Certificates last for 10 years, which is useful for long-lived local
	// development environments where you don't want to renew frequently.
	// Note: this exceeds the 825-day limit enforced by macOS/iOS for public
	// CAs, but since this is a locally-trusted CA it is not subject to that
	// restriction. See https://support.apple.com/en-us/HT210176.
	// Note: bumped to start 2 hours in the past to avoid clock skew issues
	// on VMs or containers where the system clock may lag slightly.
	// (Increased from 1 hour to 2 hours for extra safety on slow/drifting VMs.)
	notBefore := time.Now().Add(-2 * time.Hour)
	expiration := notBefore.AddDate(10, 0, 0)

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"mkcert development certificate"},
			OrganizationalUnit: []string{userAndHostname},
		},

		NotBefore: notBefore, NotAfter: expiration,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			tpl.EmailAddresses = append(tpl.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			tpl.URIs = append(tpl.URIs, uriName)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(tpl.IPAddresses) > 0 || len(tpl.DNSNames) > 0 || len(tpl.URIs) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if len(tpl.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	// IIS (the main target of PKCS #12 files), only shows the deprecated
	// Common Name in the UI. See issue #115.
	if m.pkcs12 {
		tpl.Subject.CommonName = hosts[0]
	}

	cert, err := x509.CreateCertificate(rand