//go:build !windows

package main

import "syscall"

func hideWindow(attr *syscall.SysProcAttr) {
}

func getSysProcAttr() *syscall.SysProcAttr {
    return &syscall.SysProcAttr{}
}
