//go:build linux

package limits

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeCgroupFS is an in-memory cgroupFS used by unit tests.
// Paths are treated as a flat map; parent directories are auto-created on Mkdir.
type fakeCgroupFS struct {
	// files maps absolute path -> entry. An entry with isDir=true represents a directory.
	files map[string]*fakeEntry
	// writeErrs optionally returns a specific error for WriteFile(path) or OpenFile(path) calls.
	writeErrs map[string]error
	// openErrs mirrors writeErrs but for OpenFile (subtree_control writes).
	openErrs map[string]error
	// openErrsOnce is like openErrs but the entry is deleted after the first hit, allowing
	// subsequent calls to the same path to succeed. Used for leaf-move tests where the first
	// enableControllers call fails with EBUSY and the retry after leaf-move succeeds.
	openErrsOnce map[string]error
}

type fakeEntry struct {
	content []byte
	isDir   bool
}

func newFakeCgroupFS() *fakeCgroupFS {
	return &fakeCgroupFS{
		files:        map[string]*fakeEntry{"/sys/fs/cgroup": {isDir: true}},
		writeErrs:    map[string]error{},
		openErrs:     map[string]error{},
		openErrsOnce: map[string]error{},
	}
}

// seedDir creates a directory and its parents.
func (f *fakeCgroupFS) seedDir(p string) {
	p = path.Clean(p)
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := ""
	for _, part := range parts {
		cur = cur + "/" + part
		if _, ok := f.files[cur]; !ok {
			f.files[cur] = &fakeEntry{isDir: true}
		}
	}
}

// seedFile writes content at an absolute path, creating parent dirs.
func (f *fakeCgroupFS) seedFile(p string, content string) {
	f.seedDir(path.Dir(p))
	f.files[path.Clean(p)] = &fakeEntry{content: []byte(content)}
}

func (f *fakeCgroupFS) ReadFile(p string) ([]byte, error) {
	e, ok := f.files[path.Clean(p)]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: p, Err: syscall.ENOENT}
	}
	if e.isDir {
		return nil, &fs.PathError{Op: "read", Path: p, Err: syscall.EISDIR}
	}
	return append([]byte(nil), e.content...), nil
}

func (f *fakeCgroupFS) WriteFile(p string, data []byte, perm os.FileMode) error {
	p = path.Clean(p)
	if err, ok := f.writeErrs[p]; ok {
		return &fs.PathError{Op: "write", Path: p, Err: err}
	}
	if e, ok := f.files[p]; ok && e.isDir {
		return &fs.PathError{Op: "write", Path: p, Err: syscall.EISDIR}
	}
	if _, ok := f.files[path.Dir(p)]; !ok {
		return &fs.PathError{Op: "write", Path: p, Err: syscall.ENOENT}
	}
	f.files[p] = &fakeEntry{content: append([]byte(nil), data...)}
	return nil
}

func (f *fakeCgroupFS) Mkdir(p string, perm os.FileMode) error {
	p = path.Clean(p)
	if _, ok := f.files[p]; ok {
		return &fs.PathError{Op: "mkdir", Path: p, Err: syscall.EEXIST}
	}
	if _, ok := f.files[path.Dir(p)]; !ok {
		return &fs.PathError{Op: "mkdir", Path: p, Err: syscall.ENOENT}
	}
	f.files[p] = &fakeEntry{isDir: true}
	return nil
}

func (f *fakeCgroupFS) Remove(p string) error {
	p = path.Clean(p)
	if _, ok := f.files[p]; !ok {
		return &fs.PathError{Op: "remove", Path: p, Err: syscall.ENOENT}
	}
	delete(f.files, p)
	return nil
}

func (f *fakeCgroupFS) Stat(p string) (os.FileInfo, error) {
	p = path.Clean(p)
	e, ok := f.files[p]
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: p, Err: syscall.ENOENT}
	}
	return &fakeFileInfo{name: path.Base(p), size: int64(len(e.content)), isDir: e.isDir}, nil
}

func (f *fakeCgroupFS) ReadDir(p string) ([]os.DirEntry, error) {
	p = path.Clean(p)
	if e, ok := f.files[p]; !ok || !e.isDir {
		return nil, &fs.PathError{Op: "readdir", Path: p, Err: syscall.ENOENT}
	}
	var names []string
	prefix := p + "/"
	for k := range f.files {
		if k == p {
			continue
		}
		if strings.HasPrefix(k, prefix) && !strings.Contains(strings.TrimPrefix(k, prefix), "/") {
			names = append(names, path.Base(k))
		}
	}
	sort.Strings(names)
	out := make([]os.DirEntry, 0, len(names))
	for _, n := range names {
		full := path.Join(p, n)
		e := f.files[full]
		out = append(out, &fakeDirEntry{name: n, isDir: e.isDir})
	}
	return out, nil
}

func (f *fakeCgroupFS) OpenFile(p string, flag int, perm os.FileMode) (cgroupFile, error) {
	p = path.Clean(p)
	if err, ok := f.openErrs[p]; ok {
		return nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	if _, ok := f.files[p]; !ok {
		return nil, &fs.PathError{Op: "open", Path: p, Err: syscall.ENOENT}
	}
	return &fakeWriter{fs: f, path: p}, nil
}

type fakeWriter struct {
	fs   *fakeCgroupFS
	path string
	buf  bytes.Buffer
}

func (w *fakeWriter) WriteString(s string) (int, error) {
	key := w.path + ":write"
	if err, ok := w.fs.openErrsOnce[key]; ok {
		delete(w.fs.openErrsOnce, key)
		return 0, &fs.PathError{Op: "write", Path: w.path, Err: err}
	}
	if err, ok := w.fs.openErrs[key]; ok {
		return 0, &fs.PathError{Op: "write", Path: w.path, Err: err}
	}
	w.buf.WriteString(s)
	// Append to the underlying file content on every write, mimicking
	// cgroup subtree_control semantics: the kernel stores the controller
	// name without the leading "+"/"-" prefix.
	e := w.fs.files[w.path]
	if e == nil {
		return 0, &fs.PathError{Op: "write", Path: w.path, Err: syscall.ENOENT}
	}
	token := strings.TrimPrefix(s, "+")
	token = strings.TrimPrefix(token, "-")
	sep := ""
	if len(e.content) > 0 && !bytes.HasSuffix(e.content, []byte(" ")) {
		sep = " "
	}
	e.content = append(e.content, []byte(sep+token)...)
	return len(s), nil
}

func (w *fakeWriter) Close() error { return nil }

type fakeFileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (f *fakeFileInfo) Name() string      { return f.name }
func (f *fakeFileInfo) Size() int64       { return f.size }
func (f *fakeFileInfo) Mode() os.FileMode {
	if f.isDir {
		return os.ModeDir | 0o755
	}
	return 0o644
}
func (f *fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f *fakeFileInfo) IsDir() bool        { return f.isDir }
func (f *fakeFileInfo) Sys() any           { return nil }

type fakeDirEntry struct {
	name  string
	isDir bool
}

func (d *fakeDirEntry) Name() string               { return d.name }
func (d *fakeDirEntry) IsDir() bool                { return d.isDir }
func (d *fakeDirEntry) Type() os.FileMode {
	if d.isDir {
		return os.ModeDir
	}
	return 0
}
func (d *fakeDirEntry) Info() (os.FileInfo, error) {
	return &fakeFileInfo{name: d.name, isDir: d.isDir}, nil
}

// assertSubtreeControl returns an error unless path's content contains all of
// the given controllers (used in tests).
func (f *fakeCgroupFS) assertSubtreeControl(p string, want ...string) error {
	e, ok := f.files[path.Clean(p)]
	if !ok {
		return fmt.Errorf("%s does not exist", p)
	}
	have := strings.Fields(string(e.content))
	set := map[string]bool{}
	for _, h := range have {
		set[strings.TrimPrefix(h, "+")] = true
	}
	for _, w := range want {
		if !set[w] {
			return fmt.Errorf("%s missing controller %q (have %q)", p, w, string(e.content))
		}
	}
	return nil
}

// TestFakeCgroupFS_Smoke covers basic behaviors of the fake itself.
func TestFakeCgroupFS_Smoke(t *testing.T) {
	f := newFakeCgroupFS()
	f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids")
	data, err := f.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "cpuset cpu io memory pids" {
		t.Fatalf("unexpected content: %q", data)
	}

	if err := f.Mkdir("/sys/fs/cgroup/agentsh.slice", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	entries, err := f.ReadDir("/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name() == "agentsh.slice" && e.IsDir() {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected agentsh.slice in readdir, got %v", entries)
	}
}
