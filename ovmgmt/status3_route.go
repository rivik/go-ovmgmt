package ovmgmt

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

//HEADER	ROUTING_TABLE	Virtual Address	Common Name	Real Address	Last Ref	Last Ref (time_t)

type Status3Route struct {
	VirtualAddrFlags string
	CommonName       string
	RealAddr         *IPAddrPort
	LastRefRaw       string
	LastRefTimestamp int64
	errs             []error
}

func (s Status3Route) LastRefTime() time.Time {
	return time.Unix(s.LastRefTimestamp, 0)
}

func (s Status3Route) Raw() string {
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%d\t%s", s.VirtualAddrFlags, s.CommonName, s.RealAddr, s.LastRefRaw, s.LastRefTimestamp, s.errs)
}

func (s Status3Route) String() string {
	data := fmt.Sprintf("VAddrFlags:%s\tCN:%s\tRAddr:%s\tLastRef:[%s]%d", s.VirtualAddrFlags, s.CommonName, s.RealAddr, s.LastRefRaw, s.LastRefTimestamp)
	if len(s.errs) > 0 {
		return fmt.Sprintf("InvalidRoute(%s\tParsingErrors:%s)", data, s.Error())
	}
	return fmt.Sprintf("Route(%s)", data)
}

func (s Status3Route) ParsingErrors() []error {
	return s.errs
}

func (s Status3Route) Error() string {
	if len(s.errs) == 0 {
		return ""
	}

	errstr := make([]string, len(s.errs))
	for i, err := range s.errs {
		errstr[i] = err.Error()
	}
	return strings.Join(errstr, "; ")
}

type RoutingTableHeader int

const (
	RTVirtualAddrFlags RoutingTableHeader = iota
	RTCommonName
	RTRealAddr
	RTLastRefRaw
	RTLastRefTimestamp
	RTHeaderMax
)

func NewStatus3Route(fields []string) Status3Route {
	if len(fields) < int(RTHeaderMax) {
		buf := make([]string, RTHeaderMax)
		copy(buf, fields)
		fields = buf
	}

	c := Status3Route{
		VirtualAddrFlags: fields[RTVirtualAddrFlags],
		CommonName:       fields[RTCommonName],
		LastRefRaw:       fields[RTLastRefRaw],
	}

	var err error
	c.RealAddr, err = ParseIPAddrPort(fields[RTRealAddr])
	if err != nil {
		c.errs = append(c.errs, err)
	}

	c.LastRefTimestamp, err = strconv.ParseInt(fields[RTLastRefTimestamp], 10, 64)
	if err != nil {
		c.errs = append(c.errs, err)
	}

	return c
}
