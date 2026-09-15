// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

// Command elfuse-oci manages OCI images outside the elfuse runtime.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/kong"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "elfuse-oci: %s\n", err)
		os.Exit(1)
	}
}

type cli struct {
	Pull   pullCommand   `cmd:"" help:"Pull an image into the local store"`
	Unpack unpackCommand `cmd:"" help:"Unpack a stored image into a rootfs"`
}

func newParser(stdout, stderr io.Writer, target *cli) (*kong.Kong, error) {
	return kong.New(target,
		kong.Name("elfuse-oci"),
		kong.Description("Manage OCI images for elfuse."),
		kong.Writers(stdout, stderr),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
	)
}

type parserExit struct{ code int }

func run(args []string) (err error) {
	if len(args) == 1 {
		switch args[0] {
		case "version", "-V", "--version":
			fmt.Println("elfuse-oci " + version)
			return nil
		case "help":
			args[0] = "--help"
		}
	}
	var target cli
	parser, err := newParser(os.Stdout, os.Stderr, &target)
	if err != nil {
		return err
	}
	parser.Exit = func(code int) { panic(parserExit{code}) }
	defer func() {
		if v := recover(); v != nil {
			exit, ok := v.(parserExit)
			if !ok {
				panic(v)
			}
			if exit.code != 0 {
				err = fmt.Errorf("parser exited with status %d", exit.code)
			}
		}
	}()
	ctx, err := parser.Parse(args)
	if err != nil {
		var parseErr *kong.ParseError
		if errors.As(err, &parseErr) {
			_ = parseErr.Context.PrintUsage(false)
		}
		return err
	}
	return ctx.Run()
}
