//go:build unix

package ui

import "golang.org/x/sys/unix"

// isFdTerminal returns whether the given file descriptor refers to
// an attached terminal on unix-y systems. Uses TIOCGETA (BSD) /
// TCGETS (Linux) — golang.org/x/sys/unix wraps the per-OS shape.
func isFdTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), termiosGetReq)
	return err == nil
}
