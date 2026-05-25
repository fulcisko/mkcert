// truststore.go handles installing and uninstalling the local CA
// into the system trust stores and supported browsers.

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// installCA installs the local CA certificate into the system trust store
// and any supported browser trust stores found on the system.
func (m *mkcert) installCA() {
	if m.installInSystem() {
		fmt.Println("✅ The local CA is now installed in the system trust store!")
	} else {
		fmt.Println("⚠️  The local CA could not be installed in the system trust store.")
	}

	if hasFirefox() {
		if m.installInFirefox() {
			fmt.Println("✅ The local CA is now installed in the Firefox trust store (requires browser restart)!")
		} else {
			fmt.Println("⚠️  The local CA could not be installed in the Firefox trust store.")
		}
	}
}

// uninstallCA removes the local CA certificate from the system trust store
// and any supported browser trust stores.
func (m *mkcert) uninstallCA() {
	if m.uninstallFromSystem() {
		fmt.Println("✅ The local CA is now uninstalled from the system trust store!")
	} else {
		fmt.Println("⚠️  The local CA could not be uninstalled from the system trust store.")
	}

	if hasFirefox() {
		if m.uninstallFromFirefox() {
			fmt.Println("✅ The local CA is now uninstalled from the Firefox trust store (requires browser restart)!")
		} else {
			fmt.Println("⚠️  The local CA could not be uninstalled from the Firefox trust store.")
		}
	}
}

// checkIfCAInstalled verifies whether the local CA is currently trusted
// by the system trust store.
func (m *mkcert) checkIfCAInstalled() bool {
	if m.caCert == nil {
		return false
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return false
	}

	if pool == nil {
		return false
	}

	_, err = m.caCert.Verify(x509.VerifyOptions{
		Roots: pool,
	})
	return err == nil
}

// installInSystem installs the CA into the OS-level certificate store.
// Behavior differs per operating system.
func (m *mkcert) installInSystem() bool {
	switch runtime.GOOS {
	case "darwin":
		return m.installInDarwin()
	case "linux":
		return m.installInLinux()
	case "windows":
		return m.installInWindows()
	default:
		fmt.Printf("⚠️  Unsupported OS: %s\n", runtime.GOOS)
		return false
	}
}

// uninstallFromSystem removes the CA from the OS-level certificate store.
func (m *mkcert) uninstallFromSystem() bool {
	switch runtime.GOOS {
	case "darwin":
		return m.uninstallFromDarwin()
	case "linux":
		return m.uninstallFromLinux()
	case "windows":
		return m.uninstallFromWindows()
	default:
		fmt.Printf("⚠️  Unsupported OS: %s\n", runtime.GOOS)
		return false
	}
}

// hasFirefox checks whether Mozilla Firefox is installed on the system.
func hasFirefox() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := os.Stat("/Applications/Firefox.app")
		return err == nil
	case "linux":
		_, err := exec.LookPath("firefox")
		return err == nil
	case "windows":
		paths := []string{
			fmt.Sprintf("%s\\Mozilla Firefox\\firefox.exe", os.Getenv("PROGRAMFILES")),
			fmt.Sprintf("%s\\Mozilla Firefox\\firefox.exe", os.Getenv("PROGRAMFILES(X86)")),
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return true
			}
		}
		return false
	}
	return false
}

// firefoxProfilesDir returns the default Firefox profiles directory for the current OS.
func firefoxProfilesDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "Firefox", "Profiles")
	case "linux":
		return filepath.Join(os.Getenv("HOME"), ".mozilla", "firefox")
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
	}
	return ""
}
