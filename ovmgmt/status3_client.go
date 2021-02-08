package ovmgmt

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

//HEADER	CLIENT_LIST	Common Name	Real Address	Virtual Address	Virtual IPv6 Address	Bytes Received	Bytes Sent	Connected Since	Connected Since (time_t)	Username	Client ID	Peer ID

type Status3Client struct {
	CommonName              string
	RealAddr                *IPAddrPort
	VirtualAddr             net.IP
	VirtualAddr6            net.IP
	BytesRecv               int64
	BytesSent               int64
	ConnectedSinceRaw       string
	ConnectedSinceTimestamp int64
	Username                string
	ClientId                int64
	PeerId                  int64
	DataChannelCipher       string
	errs                    []error
}

func (s Status3Client) Raw() string {
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%d\t%d\t%s\t%d\t%s\t%d\t%d\t%s\t%s", s.CommonName, s.RealAddr, s.VirtualAddr, s.VirtualAddr6, s.BytesRecv, s.BytesSent, s.ConnectedSinceRaw, s.ConnectedSinceTimestamp, s.Username, s.ClientId, s.PeerId, s.DataChannelCipher, s.errs)
}

func (s Status3Client) String() string {
	data := fmt.Sprintf("CN:%s\tRAddr:%s\tVAddr:%s\tVAddr6:%s\tBRecv:%d\tBSent:%d\tSince:[%s]%d\tUser:%s\tClientId:%d\tPeerId:%d\tDCCipher:%s", s.CommonName, s.RealAddr, s.VirtualAddr, s.VirtualAddr6, s.BytesRecv, s.BytesSent, s.ConnectedSinceRaw, s.ConnectedSinceTimestamp, s.Username, s.ClientId, s.PeerId, s.DataChannelCipher)
	if len(s.errs) > 0 {
		return fmt.Sprintf("InvalidClient(%s\tParsingErrors:%s)", data, s.Error())
	}
	return fmt.Sprintf("Client(%s)", data)
}

func (s Status3Client) ConnectedSinceTime() time.Time {
	return time.Unix(s.ConnectedSinceTimestamp, 0)
}

func (s Status3Client) ParsingErrors() []error {
	return s.errs
}

func (s Status3Client) Error() string {
	if len(s.errs) == 0 {
		return ""
	}

	errstr := make([]string, len(s.errs))
	for i, err := range s.errs {
		errstr[i] = err.Error()
	}
	return strings.Join(errstr, "; ")
}

type ClientListHeader int

const (
	CLCommonName ClientListHeader = iota
	CLRealAddr
	CLVirtualAddr
	CLVirtualAddr6
	CLBytesRecv
	CLBytesSent
	CLConnectedSinceRaw
	CLConnectedSinceTimestamp
	CLUsername
	CLClientId
	CLPeerId
	CLDataChannelCipher
	CLHeaderMax
)

func NewStatus3Client(fields []string) Status3Client {
	if len(fields) < int(CLHeaderMax) {
		buf := make([]string, CLHeaderMax)
		copy(buf, fields)
		fields = buf
	}

	c := Status3Client{
		CommonName: fields[CLCommonName],
	}

	var err error
	c.RealAddr, err = ParseIPAddrPort(fields[CLRealAddr])
	if err != nil {
		c.errs = append(c.errs, err)
	}
	c.VirtualAddr = SafeParseIP4Addr(fields[CLVirtualAddr])
	c.VirtualAddr6 = SafeParseIP6Addr(fields[CLVirtualAddr6])

	c.BytesRecv, err = strconv.ParseInt(fields[CLBytesRecv], 10, 64)
	if err != nil {
		c.errs = append(c.errs, err)
	}
	c.BytesSent, err = strconv.ParseInt(fields[CLBytesSent], 10, 64)
	if err != nil {
		c.errs = append(c.errs, err)
	}

	c.ConnectedSinceRaw = fields[CLConnectedSinceRaw]
	c.ConnectedSinceTimestamp, err = strconv.ParseInt(fields[CLConnectedSinceTimestamp], 10, 64)
	if err != nil {
		c.errs = append(c.errs, err)
	}

	c.Username = fields[CLUsername]
	c.ClientId, err = strconv.ParseInt(fields[CLClientId], 10, 64)
	if err != nil {
		c.errs = append(c.errs, err)
	}
	c.PeerId, err = strconv.ParseInt(fields[CLPeerId], 10, 64)
	if err != nil {
		c.errs = append(c.errs, err)
	}

	c.DataChannelCipher = fields[CLDataChannelCipher]

	return c
}
