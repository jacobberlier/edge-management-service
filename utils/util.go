package utils

import (
	"time"
)

// RetryWithBackoff takes a Backoff and a function to call that returns an error
// If the error is nil then the function will no longer be called.  If the error
// is Retriable then that will be used to determine if it should be retried
func RetryWithBackoff(backoff Backoff, fn func() error) error {
	var err error
	for err = fn(); true; err = fn() {
		retryable, isRetryable := err.(Retryable)

		if err == nil || isRetryable && !retryable.Retry() {
			return err
		}

		time.Sleep(backoff.Duration())
	}
	return err
}

// RetryNWithBackoff takes a Backoff, a maximum number of tries 'n', and a
// function that returns an error. The function is called until either it does
// not return an error or the maximum tries have been reached.
func RetryNWithBackoff(backoff Backoff, n int, fn func() error) error {
	var err error
	RetryWithBackoff(backoff, func() error {
		err = fn()
		n--
		if n == 0 {
			// Break out after n tries
			return nil
		}
		return err
	})
	return err
}
