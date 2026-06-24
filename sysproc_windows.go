//go:build windows

package main

import "syscall"

func hideWindow(attr *syscall.SysProcAttr) {
    attr.HideWindow = true
}

func getSysProcAttr() *syscall.SysProcAttr {
    return &syscall.SysProcAttr{HideWindow: true}
}
