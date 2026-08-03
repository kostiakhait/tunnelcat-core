// Copyright (c) 2026 Konstantin Khait

//go:build windows

package core

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	nodeIDCrypt32   = syscall.NewLazyDLL("crypt32.dll")
	nodeIDKernel32  = syscall.NewLazyDLL("kernel32.dll")
	nodeIDProtect   = nodeIDCrypt32.NewProc("CryptProtectData")
	nodeIDUnprotect = nodeIDCrypt32.NewProc("CryptUnprotectData")
	nodeIDLocalFree = nodeIDKernel32.NewProc("LocalFree")
)

type nodeIDBlob struct {
	cbData uint32
	pbData *byte
}

func nodeIDEncrypt(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("CryptProtectData: empty input")
	}
	in := &nodeIDBlob{cbData: uint32(len(plain)), pbData: &plain[0]}
	var out nodeIDBlob
	ret, _, err := nodeIDProtect.Call(
		uintptr(unsafe.Pointer(in)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer nodeIDLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	result := make([]byte, out.cbData)
	copy(result, unsafe.Slice(out.pbData, out.cbData))
	return result, nil
}

func nodeIDDecrypt(enc []byte) ([]byte, error) {
	if len(enc) == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: empty input")
	}
	in := &nodeIDBlob{cbData: uint32(len(enc)), pbData: &enc[0]}
	var out nodeIDBlob
	ret, _, err := nodeIDUnprotect.Call(
		uintptr(unsafe.Pointer(in)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer nodeIDLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	result := make([]byte, out.cbData)
	copy(result, unsafe.Slice(out.pbData, out.cbData))
	return result, nil
}
