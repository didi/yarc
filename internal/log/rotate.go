package log

import (
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

// RotateFileWriter rotates by hour.
type RotateFileWriter struct {
	file     *os.File
	currHour int64
	hours    int
	dir      string
	name     string
}

// NewRotateFileWriter create a rotate file writer
func NewRotateFileWriter(dir string, name string, hours int) *RotateFileWriter {
	if dir == "" {
		dir = "./"
	} else if dir[len(dir)-1] != '/' {
		dir += "/"
	}

	return &RotateFileWriter{
		hours: hours,
		dir:   dir,
		name:  name,
	}
}

// Write writes data
func (w *RotateFileWriter) Write(p []byte) (n int, err error) {
	if err := w.rotateByHour(); err != nil {
		return 0, err
	}
	return w.file.Write(p)
}

const rorateTimeLayout = "2006010215"

func (w *RotateFileWriter) rotateByHour() error {
	now := time.Now().Local()
	currHour := now.Unix() / 3600
	if currHour == w.currHour && w.file != nil {
		return nil
	}

	suffix := now.Format(rorateTimeLayout)
	filepath := w.dir + w.name + "." + suffix
	flag := os.O_CREATE | os.O_RDWR | os.O_APPEND
	perm := os.FileMode(0644) // -rw-r--r--
	file, err := os.OpenFile(filepath, flag, perm)
	if err != nil {
		log.Println("open file failed:", err)
		return err
	}
	w.file = file
	w.currHour = currHour
	if w.hours > 0 {
		go w.clearExpiredFiles(now)
	}
	return nil
}

func (w *RotateFileWriter) clearExpiredFiles(now time.Time) {
	entries, err := ioutil.ReadDir(w.dir)
	if err != nil {
		return
	}

	oldest := now.Add(time.Duration(w.hours) * -time.Hour)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, w.name+".") {
			continue
		}
		suffix := name[len(w.name)+1:]
		t, err := time.ParseInLocation(rorateTimeLayout, suffix, time.Local)
		if err != nil {
			continue
		}
		if t.Before(oldest) {
			os.Remove(w.dir + name)
		}
	}
}
