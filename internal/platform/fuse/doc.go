// Package fuse provides cross-platform FUSE filesystem mounting
// using cgofuse. It works with FUSE-T on macOS and WinFsp on Windows.
//
// This package requires CGO to be enabled. When CGO is disabled,
// Mount() returns an error directing users to enable CGO.
package fuse
