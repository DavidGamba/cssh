// This file is part of cssh.
//
// Copyright (C) 2016  David Gamba Rios
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package main provides a way to ssh using credentials stored in your ~/.ssh/config file.
*/
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/davidgamba/gexpect"
	"github.com/davidgamba/go-getoptions"
	// "github.com/shavac/gexpect"
)

var debugFlag bool

func debug(a ...interface{}) {
	if debugFlag {
		fmt.Fprintln(os.Stderr, a)
	}
}

func debugf(format string, a ...interface{}) {
	if debugFlag {
		fmt.Fprintf(os.Stderr, format, a)
	}
}

func sshLogin(child *gexpect.SubProcess, timeout time.Duration, passwords []string) error {
	debug("sshLogin")
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
	debugf("match: %s\n", child.Match)
	debugf("before: %s\n", child.Before)
	if idx >= 0 {
		debugf("idx: %d\n", idx)
		switch idx {
		case 0:
			debug("Answer yes")
			child.SendLine("yes")
			return sshLogin(child, timeout, passwords)
		case 1:
			if len(passwords) <= 0 {
				debug("no more passwords to try!")
				return nil
			}
			debug("send password " + passwords[0])
			child.SendLine(passwords[0])
			return sshLogin(child, timeout, passwords[1:])
		case 2:
			debug("done")
			return nil
		default:
			debug("ups!")
			return nil
		}
	}
	debug("error")
	return nil // FIXME
}

func getKeyList() []string {
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
			debug(line)
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

func readConfig(host string) []string {
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
			debug(line)
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
			debug(line)
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

func main() {
	var timeoutSeconds int
	var keyIndex int
	opt := getoptions.New()
	opt.Bool("help", false)
	opt.IntVarOptional(&keyIndex, "key", -1)
	opt.BoolVar(&debugFlag, "debug", false)
	opt.IntVar(&timeoutSeconds, "timeout", 15)
	remaining, err := opt.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	if opt.Called("help") {
		synopsis()
		os.Exit(1)
	}

	if len(remaining) < 1 {
		fmt.Fprintf(os.Stderr, "Missing hostname")
		os.Exit(1)
	}

	passwords := readConfig(remaining[0])
	debug(passwords)

	command := []string{}
	command = append(command, remaining...)
	if opt.Called("key") {
		keys := getKeyList()
		if keyIndex == -1 {
			for i, v := range keys {
				fmt.Fprintf(os.Stderr, "%d: %s\n", i, v)
			}
			os.Exit(1)
		}
		command = append(command, "-i")
		command = append(command, keys[keyIndex])
	}

	child, _ := gexpect.NewSubProcess("ssh", command...)
	debug("ssh", command)
	if err := child.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	defer child.Close()
	// if debugFlag {
	// 	child.Echo()
	// }

	sshLogin(child, time.Duration(timeoutSeconds), passwords)
	child.SendLine("set -o vi")
	child.InteractTimeout(0)
}
