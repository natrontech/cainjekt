package fsx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type WriteOptions struct {
	FallbackMode  os.FileMode
	RefuseSymlink bool
	PreserveOwner bool
}

func AtomicWrite(path string, data []byte, opt WriteOptions) error {
	if opt.FallbackMode == 0 {
		opt.FallbackMode = 0o644
	}
	if opt.RefuseSymlink {
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlink: %s", path)
		}
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cainjekt-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	mode := opt.FallbackMode
	uid, gid := -1, -1
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid = int(st.Uid)
			gid = int(st.Gid)
		}
	}

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if opt.PreserveOwner && uid >= 0 && gid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil && !errors.Is(err, os.ErrPermission) {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if dirf, err := os.Open(dir); err == nil {
		_ = dirf.Sync()
		_ = dirf.Close()
	}
	return nil
}
