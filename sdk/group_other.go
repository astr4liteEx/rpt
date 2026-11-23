//go:build !unix

package sdk

import "os/exec"

func inGroup(*exec.Cmd) {}

func killGroup(int) {}
