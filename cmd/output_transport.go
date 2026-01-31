package main

import (
	"errors"

	"github.com/netsampler/goflow2/v2/transport"
)

type outputTransport interface {
	Send(key, data []byte) error
	Close() error
}

type fanoutTransport struct {
	transports []*transport.Transport
}

func (f *fanoutTransport) Send(key, data []byte) error {
	if len(f.transports) == 0 {
		return nil
	}
	var errs []error
	for _, t := range f.transports {
		if err := t.Send(key, data); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (f *fanoutTransport) Close() error {
	var errs []error
	for _, t := range f.transports {
		if err := t.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
