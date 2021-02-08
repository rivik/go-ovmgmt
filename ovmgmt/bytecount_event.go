package ovmgmt

import (
	"fmt"
	"strconv"
)

// ByteCountClientEvent represents a periodic snapshot of data transfer in bytes
// on a VPN connection.
//
// For other OpenVPN modes, events are emitted only once per interval for the
// single connection managed by the target process, and ClientId returns
// the empty string.
type ByteCountClientEvent struct {
	body     string
	cid      int64
	bytesIn  int64
	bytesOut int64
}

func NewByteCountClientEvent(body string) (ByteCountClientEvent, error) {
	e := ByteCountClientEvent{body: body}
	bodyParts := stringsSplitNK(body, fieldSep, 3, 3)

	var err error
	e.cid, err = strconv.ParseInt(bodyParts[0], 10, 64)
	if err != nil {
		return e, err
	}

	e.bytesIn, err = strconv.ParseInt(bodyParts[1], 10, 64)
	if err != nil {
		return e, err
	}

	e.bytesOut, err = strconv.ParseInt(bodyParts[2], 10, 64)
	if err != nil {
		return e, err
	}

	return e, nil
}

func (e ByteCountClientEvent) Raw() string {
	return e.body
}

func (e ByteCountClientEvent) ClientId() int64 {
	return e.cid
}

func (e ByteCountClientEvent) BytesIn() int64 {
	return e.bytesIn
}

func (e ByteCountClientEvent) BytesOut() int64 {
	return e.bytesOut
}

func (e ByteCountClientEvent) String() string {
	return fmt.Sprintf("Client %d: %d in, %d out", e.ClientId(), e.BytesIn(), e.BytesOut())
}

// ByteCountEvent represents a periodic snapshot of data transfer in bytes
// on a VPN connection.
//
// For other OpenVPN modes, events are emitted only once per interval for the
// single connection managed by the target process, and ClientId returns
// the empty string.
type ByteCountEvent struct {
	body     string
	bytesIn  int64
	bytesOut int64
}

func NewByteCountEvent(body string) (ByteCountEvent, error) {
	e := ByteCountEvent{body: body}
	bodyParts := stringsSplitNK(body, fieldSep, 2, 2)

	var err error
	e.bytesIn, err = strconv.ParseInt(bodyParts[0], 10, 64)
	if err != nil {
		return e, err
	}
	e.bytesOut, err = strconv.ParseInt(bodyParts[1], 10, 64)
	if err != nil {
		return e, err
	}

	return e, nil
}

func (e ByteCountEvent) Raw() string {
	return e.body
}

func (e ByteCountEvent) BytesIn() int64 {
	return e.bytesIn
}

func (e ByteCountEvent) BytesOut() int64 {
	return e.bytesOut
}

func (e ByteCountEvent) String() string {
	return fmt.Sprintf("%d in, %d out", e.BytesIn(), e.BytesOut())
}
