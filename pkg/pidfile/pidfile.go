package pidfile

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/gofrs/flock"
)

// PidFile pid file
type PidFile struct {
	path string
	file *os.File
	lock *flock.Flock
}

// Open opens and locks a pid file.
func Open(path string) (*PidFile, error) {
	f := &PidFile{
		path: path,
	}

	_ = f.tryCreateFile()

	err := f.tryLockFile()
	if err != nil {
		return nil, err
	}

	err = f.openFile()
	if err != nil {
		f.Close()
		return nil, err
	}

	err = f.writePid()
	if err != nil {
		f.Close()
		return nil, err
	}

	return f, nil
}

// Close closes the pid file.
func (f *PidFile) Close() {
	if f.lock != nil {
		f.lock.Close()
		f.lock = nil
	}

	if f.file != nil {
		f.file.Close()
		f.file = nil
	}

	os.Remove(f.path)
}

func (f *PidFile) tryCreateFile() error {
	flags := os.O_CREATE | os.O_RDWR | os.O_EXCL
	perm := os.FileMode(0644) // rw-r--r--
	file, err := os.OpenFile(f.path, flags, perm)
	if err != nil {
		return err
	}

	f.file = file
	return nil
}

func (f *PidFile) tryLockFile() error {
	lock := flock.New(f.path)
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("%s was locked, another process may be started", f.path)
	}

	f.lock = lock
	return nil
}

func (f *PidFile) openFile() error {
	if f.file != nil {
		return nil
	}

	flags := os.O_RDWR | os.O_TRUNC
	file, err := os.OpenFile(f.path, flags, 0)
	if err != nil {
		return err
	}

	f.file = file
	return nil
}

func (f *PidFile) writePid() error {
	pid := os.Getpid()
	str := strconv.Itoa(pid)
	n, err := f.file.Write([]byte(str))
	if err != nil {
		return err
	}
	if n != len(str) {
		return io.ErrShortWrite
	}
	return nil
}
