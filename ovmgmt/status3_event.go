package ovmgmt

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

//TITLE	OpenVPN 2.4.8 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Oct 30 2019
//TIME	Mon Mar 23 17:53:22 2020	1584986002
//HEADER	CLIENT_LIST	Common Name	Real Address	Virtual Address	Virtual IPv6 Address	Bytes Received	Bytes Sent	Connected Since	Connected Since (time_t)	Username	Client ID	Peer ID
//HEADER	ROUTING_TABLE	Virtual Address	Common Name	Real Address	Last Ref	Last Ref (time_t)
//GLOBAL_STATS	Max bcast/mcast queue length	1
//END

const status3TitleKW = "TITLE"
const status3TimeKW = "TIME"
const status3HeaderKW = "HEADER"
const status3ClientListKW = "CLIENT_LIST"
const status3RoutingTableKW = "ROUTING_TABLE"
const status3FieldSep = "\t"

type Status3Event struct {
	title          string
	rawHumanTS     string
	rawTS          string
	ts             int64
	clients        []Status3Client
	invalidClients []Status3Client
	routes         []Status3Route
	invalidRoutes  []Status3Route
	headers        map[string][]string
	extra          map[string][]string
}

func NewStatus3Event(payload []string) (Status3Event, error) {
	se := Status3Event{}
	se.headers = make(map[string][]string)
	se.extra = make(map[string][]string)
	se.clients = make([]Status3Client, 0)
	se.routes = make([]Status3Route, 0)

	var err error
	for _, line := range payload {
		lineFields := strings.Split(line, status3FieldSep)
		lineType := lineFields[0]
		lineFields = lineFields[1:]

		switch lineType {
		case status3TitleKW:
			se.title = strings.Join(lineFields, status3FieldSep)
		case status3TimeKW:
			se.rawHumanTS = lineFields[0]
			se.rawTS = lineFields[1]
			se.ts, err = strconv.ParseInt(se.rawTS, 10, 64)
			if err != nil {
				return se, err
			}
		case status3HeaderKW:
			headerType := lineFields[0]
			se.headers[headerType] = lineFields[1:]
		case status3ClientListKW:
			c := NewStatus3Client(lineFields)
			if len(c.ParsingErrors()) > 0 {
				se.invalidClients = append(se.invalidClients, c)
			} else {
				se.clients = append(se.clients, c)
			}
		case status3RoutingTableKW:
			c := NewStatus3Route(lineFields)
			if len(c.ParsingErrors()) > 0 {
				se.invalidRoutes = append(se.invalidRoutes, c)
			} else {
				se.routes = append(se.routes, c)
			}
		default:
			se.extra[lineType] = lineFields
		}
	}
	return se, nil
}

func (se Status3Event) Raw() string {
	cl := make([]string, len(se.clients))
	for i, c := range se.clients {
		cl[i] = c.Raw()
	}
	rl := make([]string, len(se.routes))
	for i, r := range se.routes {
		rl[i] = r.Raw()
	}

	icl := make([]string, len(se.invalidClients))
	for i, c := range se.invalidClients {
		icl[i] = c.Raw()
	}
	irl := make([]string, len(se.invalidRoutes))
	for i, r := range se.invalidRoutes {
		irl[i] = r.Raw()
	}

	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s", se.title, se.rawHumanTS, se.rawTS, cl, rl,
		se.extra, icl, irl)
}

func (se Status3Event) String() string {
	cl := make([]string, len(se.clients))
	for i, c := range se.clients {
		cl[i] = c.String()
	}
	rl := make([]string, len(se.routes))
	for i, r := range se.routes {
		rl[i] = r.String()
	}

	icl := make([]string, len(se.invalidClients))
	for i, c := range se.invalidClients {
		icl[i] = c.String()
	}
	irl := make([]string, len(se.invalidRoutes))
	for i, r := range se.invalidRoutes {
		irl[i] = r.String()
	}
	return fmt.Sprintf("STATUS3:<%s\t%s\t%s\t%s\t%s\t%s>\t%s\t%s", se.title, se.rawHumanTS, se.rawTS, cl, rl,
		se.extra, icl, irl)
}

func (se Status3Event) Timestamp() int64 {
	return se.ts
}

func (se Status3Event) Time() time.Time {
	return time.Unix(se.ts, 0)
}

func (se Status3Event) Clients() []Status3Client {
	return se.clients
}

func (se Status3Event) Routes() []Status3Route {
	return se.routes
}

func (se Status3Event) InvalidClients() []Status3Client {
	return se.invalidClients
}

func (se Status3Event) InvalidRoutes() []Status3Route {
	return se.invalidRoutes
}
