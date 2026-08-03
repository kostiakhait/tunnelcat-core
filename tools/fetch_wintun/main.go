// Copyright (c) 2026 Konstantin Khait

// fetch_wintun downloads wintun-0.14.1.zip from wintun.net and extracts
// the amd64 DLL into internal/wintun/wintun.dll.
//
// This is optional: internal/wintun.Extract() now downloads the DLL itself
// at runtime on first use if it isn't already present next to the running
// executable. Run this tool instead if you want the DLL pre-fetched into
// the source tree ahead of time (e.g. for offline builds or bundling it
// into a deployment package):
//
//	go run ./tools/fetch_wintun/
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const (
	wintunURL = "https://www.wintun.net/builds/wintun-0.14.1.zip"

	// SHA-256 of wintun-0.14.1.zip (verify with: sha256sum wintun-0.14.1.zip)
	// Leave empty to skip verification.
	wintunZipSHA256 = ""

	dllInsideZip = "wintun/bin/amd64/wintun.dll"
	outPath      = "internal/wintun/wintun.dll"
)

func main() {
	// Resolve output path relative to module root (two levels up from this file).
	root, err := moduleRoot()
	if err != nil {
		fatalf("cannot locate module root: %v", err)
	}
	dst := filepath.Join(root, filepath.FromSlash(outPath))

	if _, err := os.Stat(dst); err == nil {
		fmt.Println("wintun.dll already present, skipping download.")
		return
	}

	fmt.Printf("Downloading %s …\n", wintunURL)
	data, err := download(wintunURL)
	if err != nil {
		fatalf("download: %v", err)
	}

	if wintunZipSHA256 != "" {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != wintunZipSHA256 {
			fatalf("checksum mismatch: got %s want %s", got, wintunZipSHA256)
		}
		fmt.Println("Checksum OK.")
	}

	dll, err := extractFromZip(data, dllInsideZip)
	if err != nil {
		fatalf("extract %s: %v", dllInsideZip, err)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, dll, 0644); err != nil {
		fatalf("write %s: %v", dst, err)
	}

	fmt.Printf("Saved %d bytes → %s\n", len(dll), dst)
}

func download(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec // URL is a compile-time constant
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func extractFromZip(zipData []byte, name string) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}
	for _, f := range r.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("file %q not found in zip", name)
}

func moduleRoot() (string, error) {
	// When invoked as "go run ./tools/fetch_wintun/" the working directory is
	// the module root, so just use CWD.
	return os.Getwd()
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "fetch_wintun: "+format+"\n", args...)
	os.Exit(1)
}
