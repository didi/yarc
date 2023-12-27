package log

import (
	"testing"
	"time"
)

func TestRotateWriter(t *testing.T) {
	writer := NewRotateFileWriter("./log", "record.log", 1)
	_, err := writer.Write([]byte("aha"))
	if err != nil {
		t.Fail()
		return
	}

	now := time.Now()
	writer.clearExpiredFiles(now)
}
