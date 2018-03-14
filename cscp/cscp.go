// This file is part of cssh.
//
// Copyright (C) 2016  David Gamba Rios
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package main provides a way to scp using credentials stored in your ~/.ssh/config file.
*/
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/DavidGamba/cssh/common"
	"github.com/DavidGamba/gexpect"
	// "github.com/shavac/gexpect"
	"github.com/DavidGamba/go-getoptions"
)

func synopsis() {
	synopsis := `cscp [--timeout <seconds>] [--key [<key-index>]] [--debug] [SCP ARGS and Options...]

cscp -h # show this help`
	fmt.Fprintln(os.Stderr, synopsis)
}

func main() {
	var timeoutSeconds int
	var keyIndex int
	opt := getoptions.New()
	opt.Bool("help", false)
	opt.IntVarOptional(&keyIndex, "key", -1)
	opt.BoolVar(&common.DebugFlag, "debug", false)
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

	passwords := common.ReadConfig(remaining[0])
	common.Debug(passwords)

	command := []string{}
	command = append(command, remaining...)
	if opt.Called("key") {
		keys := common.GetKeyList()
		if keyIndex == -1 {
			for i, v := range keys {
				fmt.Fprintf(os.Stderr, "%d: %s\n", i, v)
			}
			os.Exit(1)
		}
		command = append(command, "-i")
		command = append(command, keys[keyIndex])
	}

	child, _ := gexpect.NewSubProcess("scp", command...)
	common.Debug("scp", command)
	if err := child.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	defer child.Close()
	// if debugFlag {
	// 	child.Echo()
	// }

	common.SSHLogin(child, time.Duration(timeoutSeconds), passwords)
	child.InteractTimeout(0)
}
