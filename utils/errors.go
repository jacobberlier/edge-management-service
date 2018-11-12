package utils

import (
	"fmt"
	"strings"
)

//Retryable - retryable interface
type Retryable interface {
	Retry() bool
}

//DefaultRetryable - retryable default struct
type DefaultRetryable struct {
	retry bool
}

//Retry - retry
func (dr DefaultRetryable) Retry() bool {
	return dr.retry
}

//NewRetryable - create new retryable struct
func NewRetryable(retry bool) Retryable {
	return DefaultRetryable{
		retry: retry,
	}
}

//RetryableError - error interface for retryable struct
type RetryableError interface {
	Retryable
	error
}

//DefaultRetryableError - error struct for default retryable
type DefaultRetryableError struct {
	Retryable
	error
}

//NewRetryableError - creates a new retryable error
func NewRetryableError(Retryable Retryable, err error) RetryableError {
	return &DefaultRetryableError{
		Retryable,
		err,
	}
}

//AttributeError - error struct
type AttributeError struct {
	err string
}

//Error - return error string
func (e AttributeError) Error() string {
	return e.err
}

//NewAttributeError - returns initialize attribute error struct
func NewAttributeError(err string) AttributeError {
	return AttributeError{err}
}

//MultiErr - Implements error
type MultiErr struct {
	errors []error
}

//Error - Multiple errors?
func (me MultiErr) Error() string {
	ret := make([]string, len(me.errors)+1)
	ret[0] = "Multiple error:"
	for ndx, err := range me.errors {
		ret[ndx+1] = fmt.Sprintf("\t%d: %s", ndx, err.Error())
	}
	return strings.Join(ret, "\n")
}

//NewMultiError - returns an instance of the mulit error struct
func NewMultiError(errs ...error) error {
	errors := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			errors = append(errors, err)
		}
	}
	return MultiErr{errors}
}
