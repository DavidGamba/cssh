// This file is part of cssh.
//
// Copyright (C) 2016-2018  David Gamba Rios
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package common provides the common functionality that cssh and cscp share
package common

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/DavidGamba/gexpect"
	// "github.com/shavac/gexpect"
	"github.com/jsipprell/keyctl"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var logger *log.Logger = log.New(ioutil.Discard, "", log.LstdFlags)

// SetLogger - Bring your own logger instance.
func SetLogger(l *log.Logger) {
	if l != nil {
		logger = l
	}
}

// DebugFlag - Controls debug messages
var DebugFlag bool

// Debug - Prints messages to os.Stderr if DebugFlag is set
func Debug(a ...interface{}) {
	if DebugFlag {
		fmt.Fprintln(os.Stderr, a...)
	}
}

// Debugf - Prints messages to os.Stderr if DebugFlag is set
func Debugf(format string, a ...interface{}) {
	if DebugFlag {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}

// SSHLogin - Excecute interactive ssh login
func SSHLogin(child *gexpect.SubProcess, timeout time.Duration, passwords []string) error {
	Debug("sshLogin")
	idx, err := child.ExpectTimeout(
		timeout,
		// yes / no question
		regexp.MustCompile(`no\)\?\s`),
		// password
		regexp.MustCompile(`(?i:password:)\s*\r?\n?`),
		// Valid terminal session
		regexp.MustCompile(`~|>`),
		// SCP number% found
		regexp.MustCompile(`\s\d+%\s`),
		// Permission denied
		regexp.MustCompile(`Permission denied`),
		// Connection refused
		regexp.MustCompile(`connect to host \S+ port \d+: Connection refused`),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", child.Before)
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
	Debugf("match: %s\n", child.Match)
	Debugf("before: %s\n", child.Before)
	if idx >= 0 {
		Debugf("idx: %d\n", idx)
		switch idx {
		case 0:
			Debug("Answer yes")
			child.SendLine("yes")
			return SSHLogin(child, timeout, passwords)
		case 1:
			if len(passwords) <= 0 {
				Debug("no more passwords to try!")
				return nil
			}
			Debug("send password " + passwords[0])
			child.SendLine(passwords[0])
			return SSHLogin(child, timeout, passwords[1:])
		case 2:
			Debug("ssh login")
			return nil
		case 3:
			Debug("scp transfer")
			return nil
		case 4, 5:
			Debug("Error")
			return fmt.Errorf("Error: %s%s%s\n", child.Before, child.Match, child.After)
		default:
			Debug("Unknown index")
			return nil
		}
	}
	Debug("Error with index return")
	return nil // FIXME
}

// GetKeyList - Get lists of ssh keys from $HOME/.ssh/config
func GetKeyList() []string {
	var keys []string
	file, err := os.Open(os.Getenv("HOME") + "/.ssh/config")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	r := regexp.MustCompile(`# DefaultIdentityFile\s+(\S+.*?)\s*$`)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if r.MatchString(line) {
			Debug(line)
			m := r.FindStringSubmatch(line)
			keys = append(keys, strings.Split(m[1], " ")...)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	file.Close()

	home := os.Getenv("HOME")
	for i, v := range keys {
		keys[i] = strings.Replace(v, "~", home, 1)
	}

	return keys
}

// ReadConfig - Reads the $HOME/.ssh/config for given host
func ReadConfig(host string) []string {
	var passwords []string
	file, err := os.Open(os.Getenv("HOME") + "/.ssh/config")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	r := regexp.MustCompile(`Host ` + host + ` #\s+(\S+.*?)\s*$`)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if r.MatchString(line) {
			Debug(line)
			m := r.FindStringSubmatch(line)
			passwords = append(passwords, strings.Split(m[1], " ")...)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	file.Close()

	file, err = os.Open(os.Getenv("HOME") + "/.ssh/config")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	r = regexp.MustCompile(`Host \* #\s+(\S+.*?)\s*$`)
	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if r.MatchString(line) {
			Debug(line)
			m := r.FindStringSubmatch(line)
			passwords = append(passwords, strings.Split(m[1], " ")...)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return passwords
}

func synopsis() {
	synopsis := `cssh <hostname> [--timeout <seconds>] [--key [<key-index>]] [--debug] [SSH Options...]

cssh -h # show this help`
	fmt.Fprintln(os.Stderr, synopsis)
}

// GetPassword - Gets a secret from the User Session Keyring.
// If the key doesn't exist, it asks the user to enter the password value.
func GetPassword(name string) ([]byte, error) {
	// Create session
	keyring, err := keyctl.UserSessionKeyring()
	if err != nil {
		return nil, fmt.Errorf("couldn't create keyring session: %w", err)
	}

	// Retrieve
	key, err := keyring.Search(name)
	if err == nil {
		data, err := key.Get()
		if err != nil {
			return nil, fmt.Errorf("couldn't retrieve key data: %w", err)
		}
		info, _ := key.Info()
		logger.Printf("Found key: %+v", info)
		return data, nil
	}

	// If not found promt user
	fmt.Printf("Enter '%s' password: ", name)
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	return password, nil
}

// CachePassword - Saves a secret to the User Session Keyring.
// It will cache the secret for a given number of seconds.
//
// To invalidate a password, save it with a 1 second timeout.
func CachePassword(name, password string, timeoutSeconds uint) error {
	// Create session
	keyring, err := keyctl.UserSessionKeyring()
	if err != nil {
		return fmt.Errorf("couldn't create keyring session: %w", err)
	}

	// Store key
	keyring.SetDefaultTimeout(timeoutSeconds)
	key, err := keyring.Add(name, []byte(password))
	if err != nil {
		return fmt.Errorf("couldn't store '%s': %s", name, err)
	}
	info, _ := key.Info()
	logger.Printf("Saved key: %+v", info)
	return nil
}

// UnlockPrivateKey - given a private key path check if it is locked and unlock it.
func UnlockPrivateKey(file string) (ssh.Signer, error) {
	logger.Printf("UnlockPrivateKey %s\n", file)
	// Create the Signer for this private key.
	// Assumes it is encrypted.
	key, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key '%s', %w", file, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err == nil {
		logger.Println("UnlockPrivateKey unlocked key")
		return signer, nil
	}
	// TODO: Figure out the signature of the error before continuing
	logger.Println("UnlockPrivateKey locked key")

	// Retrieve existing password or ask user to add one
	data, err := GetPassword(file)
	if err != nil {
		return signer, err
	}

	err = CachePassword(file, string(data), uint(28800))
	if err != nil {
		return signer, err
	}

	signer, err = ssh.ParsePrivateKeyWithPassphrase(key, data)
	if err != nil {
		return signer, fmt.Errorf("unable to parse private key '%s', %w", file, err)
	}
	return signer, nil
}

// SSHClient - Creates an SSH client.
// A client does the key exchange against a server.
// This allows to re-use the same SSH tcp connection for multiple sessions.
// Use example:
//
//     signer, err := UnlockPrivateKey(key)
//     if err != nil {
//			return fmt.Errorf(os.Stderr, "ERROR: failed to unlock private key '%s' %w\n", key, err)
//     }
//     client, err := SSHClient(sshTimeout, signer, user, host)
//     if err != nil {
//			// To capture which hosts don't have a DNS entry
//     	var dnsErr *net.DNSError
//     	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
//     		logger.Printf("Error is of type DNSError not found\n")
//     		return err
//     	}
//      return err
//     }
func SSHClient(sshTimeout time.Duration, signer ssh.Signer, user, host string) (*ssh.Client, error) {
	logger.Printf("SSHClient %v, %s, %s\n", sshTimeout, user, host)
	// Create client config
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         sshTimeout,
	}
	// Connect to ssh server
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", host), config)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to '%s': %w", host, err)
	}
	return client, nil
}

// SSHSession - Creates an SSH session that can be signaled with SIGTERM for cancelation.
// Kill with: session.Signal(ssh.SIGTERM)
func SSHSession(client *ssh.Client, host string) (*ssh.Session, error) {
	logger.Printf("SSHSession %s\n", host)
	// Create a session
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("unable to create session to '%s': %w", host, err)
	}
	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0, // disable echoing
		ssh.ECHOCTL:       0,
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	w, h := 80, 40
	fd := int(os.Stdin.Fd())
	if terminal.IsTerminal(fd) {
		logger.Printf("SSHSession Raw mode\n")
		state, err := terminal.MakeRaw(fd)
		if err != nil {
			logger.Printf("SSHSession Raw mode error: %s\n", err)
			fmt.Println(err)
		}
		defer terminal.Restore(fd, state)

		w, h, err = terminal.GetSize(fd)
		if err != nil {
			fmt.Println(err)
		}
	}

	// Request pseudo terminal
	// Kill with: session.Signal(ssh.SIGTERM)
	// if err := session.RequestPty("xterm", h, w, modes); err != nil {
	if err := session.RequestPty("vt100", h, w, modes); err != nil {
		session.Close()
		return nil, fmt.Errorf("request for pseudo terminal failed to '%s': %w", host, err)
	}
	return session, nil
}
