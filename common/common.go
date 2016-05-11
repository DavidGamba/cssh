// This file is part of cssh.
//
// Copyright (C) 2016  David Gamba Rios
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package common provides the common functionality that cssh and cscp share
package common

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/davidgamba/gexpect"
	// "github.com/shavac/gexpect"
)

// DebugFlag - Controls debug messages
var DebugFlag bool

// Debug - Prints messages to os.Stderr if DebugFlag is set
func Debug(a ...interface{}) {
	if DebugFlag {
		fmt.Fprintln(os.Stderr, a)
	}
}

// Debugf - Prints messages to os.Stderr if DebugFlag is set
func Debugf(format string, a ...interface{}) {
	if DebugFlag {
		fmt.Fprintf(os.Stderr, format, a)
	}
}

// SSHLogin - Excecute interactive ssh login
func SSHLogin(child *gexpect.SubProcess, timeout time.Duration, passwords []string) error {
	Debug("sshLogin")
	idx, err := child.ExpectTimeout(
		timeout*time.Second,
		regexp.MustCompile(`no\)\?\s`),
		regexp.MustCompile(`(?i:password:)\s*\r?\n?`),
		regexp.MustCompile(`~|>`),
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
			Debug("done")
			return nil
		default:
			Debug("ups!")
			return nil
		}
	}
	Debug("error")
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
