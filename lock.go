package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockDatabase takes an exclusive lock on a file beside the database, so a
// second gateway process on the same database refuses to start. The lock is
// held by the open file and is released when the process exits, however it
// exits. Commands that open the database briefly (enrolling an administrator's
// authenticator, the health check) do not take it.
func lockDatabase(dbPath string) (func(), error) {
	path := dbPath + ".lock"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("database lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another gateway is already running on %s; only one may use a database", dbPath)
		}
		return nil, fmt.Errorf("database lock %s: %w", path, err)
	}
	return func() { f.Close() }, nil
}
