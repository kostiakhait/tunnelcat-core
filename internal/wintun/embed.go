// Copyright (c) 2026 Konstantin Khait

//go:build windows

// Package wintun fetches the WinTun driver DLL at runtime (on first use) and
// extracts it to the directory of the running executable.
//
// Unlike an earlier go:embed-based version, this has no compile-time
// dependency on wintun.dll being present — that broke `go build` for any
// downstream consumer of this module, since the DLL is deliberately not
// committed to this repo (see tools/fetch_wintun and the README's Wintun
// licensing note). Extract() now downloads it directly instead.
package wintun

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const (
	wintunURL    = "https://www.wintun.net/builds/wintun-0.14.1.zip"
	dllInsideZip = "wintun/bin/amd64/wintun.dll"
)

// Extract downloads wintun.dll (if not already present next to the running
// executable) and writes it there. wintun's LoadLibraryEx call searches
// APPLICATION_DIR first, so the DLL must live beside the .exe.
func Extract() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("wintun extract: executable path: %w", err)
	}
	dst := filepath.Join(filepath.Dir(exe), "wintun.dll")

	if _, err := os.Stat(dst); err == nil {
		return nil // already extracted
	}

	dll, err := fetch()
	if err != nil {
		return fmt.Errorf("wintun extract: fetch: %w", err)
	}

	if err := os.WriteFile(dst, dll, 0644); err != nil {
		return fmt.Errorf("wintun extract: write %s: %w", dst, err)
	}
	return nil
}

func fetch() ([]byte, error) {
	resp, err := http.Get(wintunURL) //nolint:gosec // URL is a compile-time constant
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}
	for _, f := range r.File {
		if f.Name == dllInsideZip {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("file %q not found in %s", dllInsideZip, wintunURL)
}
