// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUsageAndErrors(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() { err = run(nil) })
	if err == nil {
		t.Fatal("missing command must fail")
	}
	mustContain(t, stdout, "Usage: elfuse-oci <command>", "pull", "unpack")
	if stderr != "" {
		t.Fatalf("parse error wrote to stderr: %q", stderr)
	}

	stdout, stderr = captureOutput(t, func() { err = run([]string{"bogus"}) })
	if err == nil || !strings.Contains(err.Error(), "unexpected argument bogus") {
		t.Fatalf("unknown command error = %v", err)
	}
	mustContain(t, stdout, "Usage: elfuse-oci <command>", "pull", "unpack")
	if stderr != "" {
		t.Fatalf("unknown command wrote to stderr: %q", stderr)
	}

	for cmd, flag := range map[string]string{"pull": "--timeout", "unpack": "--rootfs"} {
		stdout, stderr = captureOutput(t, func() { err = run([]string{cmd, "--nope", "x"}) })
		if err == nil || !strings.Contains(err.Error(), "unknown flag --nope") {
			t.Fatalf("%s: unknown flag error = %v", cmd, err)
		}
		mustContain(t, stdout, "Usage: elfuse-oci "+cmd, "--platform", "--store", flag)
		if stderr != "" {
			t.Fatalf("%s: unknown flag wrote to stderr: %q", cmd, stderr)
		}
	}
}

func TestVersionOnStdout(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() { err = run([]string{"version"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout, "elfuse-oci ") || stderr != "" {
		t.Fatalf("version stdout = %q stderr = %q", stdout, stderr)
	}
}

func TestSubcommandHelpIsSuccess(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() { err = run([]string{"pull", "-h"}) })
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, stdout, "Usage: elfuse-oci pull", "--platform", "--store", "--timeout")
	if stderr != "" {
		t.Fatalf("help wrote to stderr: %q", stderr)
	}
}

func TestParserWritesToConfiguredStreams(t *testing.T) {
	var target cli
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	parser, err := newParser(&stdout, &stderr, &target)
	if err != nil {
		t.Fatal(err)
	}
	_, err = parser.Parse([]string{"pull", "--nope", "x"})
	if err == nil {
		t.Fatal("unknown flag must fail")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("parse wrote stdout %q stderr %q", stdout.String(), stderr.String())
	}
}
