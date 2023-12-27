package model

import "time"

// Thread saves thread info
type Thread struct {
	ID         uint64
	ParentID   uint64
	LastAccess time.Time
}
