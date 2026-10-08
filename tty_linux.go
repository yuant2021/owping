package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"
)

// readPassphrase prompts on the controlling terminal and reads a line with
// echo disabled, restoring the terminal even if interrupted.
func readPassphrase(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer tty.Close()
	fd := tty.Fd()

	var saved syscall.Termios
	if err := ioctl(fd, syscall.TCGETS, &saved); err != nil {
		return nil, err
	}
	noEcho := saved
	noEcho.Lflag &^= syscall.ECHO
	noEcho.Lflag |= syscall.ICANON
	if err := ioctl(fd, syscall.TCSETS, &noEcho); err != nil {
		return nil, err
	}
	restore := func() { ioctl(fd, syscall.TCSETS, &saved) }
	defer restore()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sigs:
			restore()
			fmt.Fprintln(tty)
			os.Exit(2)
		case <-done:
		}
	}()

	fmt.Fprint(tty, prompt)
	line, err := bufio.NewReader(tty).ReadString('\n')
	fmt.Fprintln(tty)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func ioctl(fd uintptr, req uintptr, t *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(t))); errno != 0 {
		return errno
	}
	return nil
}
