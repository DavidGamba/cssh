// This file is part of cssh.
//
// Copyright (C) 2016-2018  David Gamba Rios
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package main provides a way to ssh using credentials stored in your ~/.ssh/config file.
*/
package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DavidGamba/cssh/common"
	"golang.org/x/crypto/ssh/terminal"

	// "github.com/DavidGamba/gexpect"
	// "github.com/shavac/gexpect"
	"github.com/DavidGamba/go-getoptions"
)

var logger *log.Logger = log.New(ioutil.Discard, "", log.LstdFlags)

func synopsis() {
	synopsis := `cssh <hostname> [--timeout <seconds>] [--key [<key-index>]] [--debug] [SSH Options...]

cssh -h # show this help`
	fmt.Fprintln(os.Stderr, synopsis)
}

func main() {
	var timeoutSeconds int
	var keyIndex int
	opt := getoptions.New()
	opt.SetUnknownMode(getoptions.Pass)
	opt.Bool("help", false)
	opt.IntVarOptional(&keyIndex, "key", -1)
	opt.BoolVar(&common.DebugFlag, "debug", false)
	opt.IntVar(&timeoutSeconds, "timeout", 5)
	remaining, err := opt.Parse(os.Args[1:])
	if opt.Called("help") {
		synopsis()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
	if opt.Called("debug") {
		logger.SetOutput(os.Stderr)
		common.SetLogger(logger)
	}

	if len(remaining) < 1 {
		fmt.Fprintf(os.Stderr, "Missing hostname")
		os.Exit(1)
	}

	passwords := common.ReadConfig(remaining[0])
	common.Debug(passwords)

	var key string
	if opt.Called("key") {
		keys := common.GetKeyList()
		if keyIndex == -1 {
			for i, v := range keys {
				fmt.Fprintf(os.Stderr, "%d: %s\n", i, v)
			}
			os.Exit(1)
		}
		key = keys[keyIndex]
	}
	err = sshRun(time.Duration(300)*time.Second, key, remaining[0], "ubuntu")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func sshRun(sshTimeout time.Duration, key, host, user string) error {
	logger.Printf("sshRun %v, %s %s %s\n", sshTimeout, key, host, user)
	signer, err := common.UnlockPrivateKey(key)
	if err != nil {
		return fmt.Errorf("ERROR: failed to unlock private key '%s' %w\n", key, err)
	}
	client, err := common.SSHClient(sshTimeout, signer, user, host)
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := common.SSHSession(client, host)
	if err != nil {
		return fmt.Errorf("failed to create ssh session to '%s': %w", host, err)
	}
	defer session.Close()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	// session.Stdin = os.Stdin
	stdin, _ := session.StdinPipe()
	go func() {
		io.Copy(stdin, os.Stdin)
	}()
	err = session.Shell()
	if err != nil {
		return err
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGWINCH, os.Interrupt)
	go func() {
		for {
			switch <-signals {
			case syscall.SIGWINCH:
				fd := int(os.Stdout.Fd())
				w, h, _ := terminal.GetSize(fd)
				session.WindowChange(h, w)
			case os.Interrupt:
				stdin.Write([]byte("\x03"))
				// // Doesn't work
				// // fmt.Println("^C")
				// // fmt.Fprint(os.Stdin, "\n")
				//
				// // Doesn't work
				// // stdin.Write([]byte("^C\n"))
				//
				// // Doesn't work
				// // stdin.Write([]byte("^C"))
				//
				// // Doesn't work
				// // fmt.Fprint(stdin, "\x03")
				//
				// // Doesn't work
				// err := session.Signal(ssh.SIGINT)
				// if err != nil {
				// 	fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
				// }
				// fmt.Println("\nSignal sent")
			}
		}
	}()

	err = session.Wait()
	if err != nil {
		return err
	}

	return nil
}
