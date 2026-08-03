// Copyright (c) 2026 Konstantin Khait

//go:build !windows

package core

// On non-Windows platforms (Android, Linux) the private key is stored as
// plaintext in appDataDir — the OS sandbox (Android app isolation, Unix
// file permissions) provides the equivalent protection.

func nodeIDEncrypt(plain []byte) ([]byte, error) { return plain, nil }
func nodeIDDecrypt(enc []byte) ([]byte, error)   { return enc, nil }
