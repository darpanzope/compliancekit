//go:build darwin

package ui

import "golang.org/x/sys/unix"

// Darwin / *BSD use TIOCGETA for the termios fetch ioctl.
const termiosGetReq = unix.TIOCGETA
