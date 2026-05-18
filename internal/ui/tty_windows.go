//go:build windows

package ui

import "golang.org/x/sys/windows"

// isFdTerminal returns whether the given Windows handle refers to
// an attached console (ConsoleScreenBufferInfo succeeds only on
// console handles).
func isFdTerminal(fd uintptr) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}
