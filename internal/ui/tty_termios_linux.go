//go:build linux

package ui

import "golang.org/x/sys/unix"

// Linux uses TCGETS for the termios fetch ioctl.
const termiosGetReq = unix.TCGETS
