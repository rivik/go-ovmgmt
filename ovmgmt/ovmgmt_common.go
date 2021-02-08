package ovmgmt

import (
	"errors"
	"net"
	"strconv"
)

type OVpnError struct {
	msg string
}

func (e *OVpnError) Error() string {
	return e.msg
}

func NewOVpnError(m string) *OVpnError {
	return &OVpnError{msg: m}
}

type IPAddrPort struct {
	IP   net.IP
	Port int
}

func ParseIPAddrPort(s string) (*IPAddrPort, error) {
	host, sPort, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}

	ip, err := ParseIPAddr(host)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(sPort)
	if err != nil {
		return nil, err
	}

	return &IPAddrPort{ip, port}, err
}

func (ia *IPAddrPort) String() string {
	return net.JoinHostPort(ia.IP.String(), strconv.Itoa(ia.Port))
}

func ParseIPAddr(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, errors.New("can't parse ip from " + s)
	}
	return ip, nil
}

func SafeParseIP4Addr(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.ParseIP("0.0.0.0")
	}
	return ip
}

func SafeParseIP6Addr(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.ParseIP("::")
	}
	return ip
}
