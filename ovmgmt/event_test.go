package ovmgmt

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// A key requirement of our event parsing is that it must never cause a
// panic, even if the OpenVPN process sends us malformed garbage.
//
// Therefore most of the tests in here are testing various tortured error
// cases, which are all expected to produce an event object, though the
// contents of that event object will be nonsensical if the OpenVPN server
// sends something nonsensical.

func TestMalformedEvent(t *testing.T) {
	testCases := []string{
		"",
		"HTTP/1.1 200 OK",
		"     ",
		"\x00",
	}

	for i, testCase := range testCases {
		_, kw, body := splitEvent(testCase)
		event := upgradeEvent(kw, body)

		var malformed MalformedEvent
		var ok bool
		if malformed, ok = event.(MalformedEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, malformed)
			continue
		}

		wantString := fmt.Sprintf("Malformed Event %q", testCase)
		if gotString := malformed.String(); gotString != wantString {
			t.Errorf("test %d String returned %q; want %q", i, gotString, wantString)
		}
	}
}

func TestUnknownEvent(t *testing.T) {
	type TestCase struct {
		Input    string
		WantType string
		WantBody string
	}
	testCases := []TestCase{
		{
			Input:    "DUMMY:baz",
			WantType: "DUMMY",
			WantBody: "baz",
		},
		{
			Input:    "DUMMY:",
			WantType: "DUMMY",
			WantBody: "",
		},
		{
			Input:    "DUMMY:abc,123,456",
			WantType: "DUMMY",
			WantBody: "abc,123,456",
		},
	}

	for i, testCase := range testCases {
		_, kw, body := splitEvent(testCase.Input)
		event := upgradeEvent(kw, body)

		var unk UnknownEvent
		var ok bool
		if unk, ok = event.(UnknownEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, unk)
			continue
		}

		if got, want := unk.Type(), testCase.WantType; got != want {
			t.Errorf("test %d Type returned %q; want %q", i, got, want)
		}
		if got, want := unk.Body(), testCase.WantBody; got != want {
			t.Errorf("test %d Body returned %q; want %q", i, got, want)
		}
	}
}

func TestHoldEvent(t *testing.T) {
	testCases := []string{
		"HOLD:",
		"HOLD:waiting for hold release",
	}

	for i, testCase := range testCases {
		_, kw, body := splitEvent(testCase)
		event := upgradeEvent(kw, body)

		var hold HoldEvent
		var ok bool
		if hold, ok = event.(HoldEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, hold)
			continue
		}
	}
}

func TestEchoEvent(t *testing.T) {
	type TestCase struct {
		Input       string
		WantErr     error
		WantTS      int64
		WantTime    time.Time
		WantMessage string
	}
	atoiZ, atoiSyntaxErr := strconv.ParseInt("", 10, 64)
	testCases := []TestCase{
		{
			Input:       "ECHO:123,foo",
			WantErr:     nil,
			WantTS:      123,
			WantTime:    time.Unix(123, 0),
			WantMessage: "foo",
		},
		{
			Input:       "ECHO:123,",
			WantErr:     nil,
			WantTS:      123,
			WantTime:    time.Unix(123, 0),
			WantMessage: "",
		},
		{
			Input:       "ECHO:,foo",
			WantErr:     atoiSyntaxErr,
			WantTS:      atoiZ,
			WantTime:    time.Unix(0, 0),
			WantMessage: "foo",
		},
		{
			Input:       "ECHO:,",
			WantErr:     atoiSyntaxErr,
			WantTS:      atoiZ,
			WantTime:    time.Unix(0, 0),
			WantMessage: "",
		},
		{
			Input:       "ECHO:",
			WantErr:     ErrNoMsgFieldSep,
			WantTS:      atoiZ,
			WantTime:    time.Unix(0, 0),
			WantMessage: "",
		},
	}

	for i, testCase := range testCases {
		_, kw, body := splitEvent(testCase.Input)
		event := upgradeEvent(kw, body)

		var echo EchoEvent
		var ok bool

		if testCase.WantErr != nil {
			evt, ok := event.(InvalidEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, event, evt)
				continue
			}

			echo, ok = evt.Origin().(EchoEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, evt.Origin(), echo)
				continue
			}
			if evt.Error() != testCase.WantErr.Error() {
				t.Errorf("test %d InvalidEvent.Error returned %q; want %q", i, evt.Error(), testCase.WantErr)
				continue
			}
		} else if echo, ok = event.(EchoEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, echo)
			continue
		}

		if got, want := echo.Timestamp(), testCase.WantTS; got != want {
			t.Errorf("test %d Timestamp returned %q; want %q", i, got, want)
		}

		if got, want := echo.Message(), testCase.WantMessage; got != want {
			t.Errorf("test %d Message returned %q; want %q", i, got, want)
		}
	}
}

func TestLogEvent(t *testing.T) {
	type TestCase struct {
		Input     string
		WantErr   error
		WantTS    int64
		WantTime  time.Time
		WantFlags string
		WantMsg   string
	}
	atoiZ, atoiSyntaxErr := strconv.ParseInt("", 10, 64)
	testCases := []TestCase{
		{
			Input:     "LOG:",
			WantErr:   atoiSyntaxErr,
			WantTS:    atoiZ,
			WantTime:  time.Unix(0, 0),
			WantFlags: "",
			WantMsg:   "",
		},
		{
			Input:     "LOG:,",
			WantErr:   atoiSyntaxErr,
			WantTS:    atoiZ,
			WantTime:  time.Unix(0, 0),
			WantFlags: "",
			WantMsg:   "",
		},
		{
			Input:     "LOG:,,",
			WantErr:   atoiSyntaxErr,
			WantTS:    atoiZ,
			WantTime:  time.Unix(0, 0),
			WantFlags: "",
			WantMsg:   "",
		},
		{
			Input:     "LOG:,,,,,",
			WantErr:   atoiSyntaxErr,
			WantTS:    atoiZ,
			WantTime:  time.Unix(0, 0),
			WantFlags: "",
			WantMsg:   ",,,",
		},
		{
			Input:     "LOG:1584536294,IW,log message",
			WantErr:   nil,
			WantTS:    int64(1584536294),
			WantTime:  time.Unix(1584536294, 0),
			WantFlags: "IW",
			WantMsg:   "log message",
		},
	}

	for i, testCase := range testCases {
		_, kw, body := splitEvent(testCase.Input)
		event := upgradeEvent(kw, body)

		var st LogEvent
		var ok bool
		if testCase.WantErr != nil {
			evt, ok := event.(InvalidEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, event, evt)
				continue
			}

			st, ok = evt.Origin().(LogEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, evt.Origin(), st)
				continue
			}
			if evt.Error() != testCase.WantErr.Error() {
				t.Errorf("test %d InvalidEvent.Error returned %q; want %q", i, evt.Error(), testCase.WantErr)
				continue
			}
		} else if st, ok = event.(LogEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, st)
			continue
		}

		if got, want := st.Timestamp(), testCase.WantTS; got != want {
			t.Errorf("test %d Timestamp returned %q; want %q", i, got, want)
		}

		if got, want := st.Time(), testCase.WantTime; got != want {
			t.Errorf("test %d Time returned %q; want %q", i, got, want)
		}

		if got, want := st.RawFlags(), testCase.WantFlags; got != want {
			t.Errorf("test %d RawFlags returned %q; want %q", i, got, want)
		}

		if got, want := st.Message(), testCase.WantMsg; got != want {
			t.Errorf("test %d Message returned %q; want %q", i, got, want)
		}
	}
}

func TestStateEvent(t *testing.T) {
	type TestCase struct {
		Input          string
		WantErr        error
		WantTS         int64
		WantTime       time.Time
		WantState      string
		WantDesc       string
		WantLocalAddr  string
		WantRemoteAddr string
	}
	atoiZ, atoiSyntaxErr := strconv.ParseInt("", 10, 64)
	testCases := []TestCase{
		{
			Input:          "STATE:",
			WantErr:        atoiSyntaxErr,
			WantTS:         atoiZ,
			WantTime:       time.Unix(0, 0),
			WantState:      "",
			WantDesc:       "",
			WantLocalAddr:  "",
			WantRemoteAddr: "",
		},
		{
			Input:          "STATE:,",
			WantErr:        atoiSyntaxErr,
			WantTS:         atoiZ,
			WantTime:       time.Unix(0, 0),
			WantState:      "",
			WantDesc:       "",
			WantLocalAddr:  "",
			WantRemoteAddr: "",
		},
		{
			Input:          "STATE:,,,,",
			WantErr:        atoiSyntaxErr,
			WantTS:         atoiZ,
			WantTime:       time.Unix(0, 0),
			WantState:      "",
			WantDesc:       "",
			WantLocalAddr:  "",
			WantRemoteAddr: "",
		},
		{
			Input:          "STATE:123,CONNECTED,good,172.16.0.1,192.168.4.1",
			WantErr:        nil,
			WantTS:         123,
			WantTime:       time.Unix(123, 0),
			WantState:      "CONNECTED",
			WantDesc:       "good",
			WantLocalAddr:  "172.16.0.1",
			WantRemoteAddr: "192.168.4.1",
		},
		{
			Input:          "STATE:123,RECONNECTING,SIGHUP,,",
			WantErr:        nil,
			WantTS:         123,
			WantTime:       time.Unix(123, 0),
			WantState:      "RECONNECTING",
			WantDesc:       "SIGHUP",
			WantLocalAddr:  "",
			WantRemoteAddr: "",
		},
		{
			Input:          "STATE:123,RECONNECTING,SIGHUP,,,extra",
			WantErr:        nil,
			WantTS:         123,
			WantTime:       time.Unix(123, 0),
			WantState:      "RECONNECTING",
			WantDesc:       "SIGHUP",
			WantLocalAddr:  "",
			WantRemoteAddr: "",
		},
	}

	for i, testCase := range testCases {
		_, kw, body := splitEvent(testCase.Input)
		event := upgradeEvent(kw, body)

		var st StateEvent
		var ok bool
		if testCase.WantErr != nil {
			evt, ok := event.(InvalidEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, event, evt)
				continue
			}

			st, ok = evt.Origin().(StateEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, evt.Origin(), st)
				continue
			}
			if evt.Error() != testCase.WantErr.Error() {
				t.Errorf("test %d InvalidEvent.Error returned %q; want %q", i, evt.Error(), testCase.WantErr)
				continue
			}
		} else if st, ok = event.(StateEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, st)
			continue
		}

		if got, want := st.Timestamp(), testCase.WantTS; got != want {
			t.Errorf("test %d Timestamp returned %q; want %q", i, got, want)
		}

		if got, want := st.NewState(), testCase.WantState; got != want {
			t.Errorf("test %d NewState returned %q; want %q", i, got, want)
		}
		if got, want := st.Description(), testCase.WantDesc; got != want {
			t.Errorf("test %d Description returned %q; want %q", i, got, want)
		}
		if got, want := st.LocalTunnelAddr(), testCase.WantLocalAddr; got != want {
			t.Errorf("test %d LocalTunnelAddr returned %q; want %q", i, got, want)
		}
		if got, want := st.RemoteAddr(), testCase.WantRemoteAddr; got != want {
			t.Errorf("test %d RemoteAddr returned %q; want %q", i, got, want)
		}
	}
}

func TestByteCountEvent(t *testing.T) {
	type TestCase struct {
		Input        string
		WantErr      error
		WantBytesIn  int64
		WantBytesOut int64
	}

	_, atoiSyntaxErr := strconv.ParseInt("", 10, 64)
	_, atoiSyntaxErr2 := strconv.ParseInt("bad", 10, 64)
	_, atoiSyntaxErr3 := strconv.ParseInt("2,3", 10, 64)
	testCases := []TestCase{
		{
			Input:        "BYTECOUNT:",
			WantErr:      atoiSyntaxErr,
			WantBytesIn:  0,
			WantBytesOut: 0,
		},
		{
			Input:        "BYTECOUNT:123,456",
			WantErr:      nil,
			WantBytesIn:  123,
			WantBytesOut: 456,
		},
		{
			Input:        "BYTECOUNT:,",
			WantErr:      atoiSyntaxErr,
			WantBytesIn:  0,
			WantBytesOut: 0,
		},
		{
			Input:        "BYTECOUNT:5,",
			WantErr:      atoiSyntaxErr,
			WantBytesIn:  5,
			WantBytesOut: 0,
		},
		{
			Input:        "BYTECOUNT:,6",
			WantErr:      atoiSyntaxErr,
			WantBytesIn:  0,
			WantBytesOut: 0,
		},
		{
			Input:        "BYTECOUNT:6",
			WantErr:      atoiSyntaxErr,
			WantBytesIn:  6,
			WantBytesOut: 0,
		},
		{
			Input:        "BYTECOUNT:bad,bad",
			WantErr:      atoiSyntaxErr2,
			WantBytesIn:  0,
			WantBytesOut: 0,
		},
		{
			Input:        "BYTECOUNT:1,2,3",
			WantErr:      atoiSyntaxErr3,
			WantBytesIn:  1,
			WantBytesOut: 0,
		},
	}

	for i, testCase := range testCases {
		_, kw, body := splitEvent(testCase.Input)
		event := upgradeEvent(kw, body)

		var bc ByteCountEvent
		var ok bool
		if testCase.WantErr != nil {
			evt, ok := event.(InvalidEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, event, evt)
				continue
			}

			bc, ok = evt.Origin().(ByteCountEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, evt.Origin(), bc)
				continue
			}
			if evt.Error() != testCase.WantErr.Error() {
				t.Errorf("test %d InvalidEvent.Error returned %q; want %q", i, evt.Error(), testCase.WantErr)
				continue
			}
		} else if bc, ok = event.(ByteCountEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, bc)
			continue
		}

		if got, want := bc.BytesIn(), testCase.WantBytesIn; got != want {
			t.Errorf("test %d BytesIn returned %d; want %d", i, got, want)
		}
		if got, want := bc.BytesOut(), testCase.WantBytesOut; got != want {
			t.Errorf("test %d BytesOut returned %d; want %d", i, got, want)
		}
	}
}

func TestByteCountClientEvent(t *testing.T) {
	type TestCase struct {
		Input        string
		WantErr      error
		WantClientId int64
		WantBytesIn  int64
		WantBytesOut int64
	}

	_, atoiSyntaxErr := strconv.ParseInt("", 10, 64)
	_, atoiSyntaxErr2 := strconv.ParseInt("bad", 10, 64)
	testCases := []TestCase{
		{
			// Intentionally malformed BYTECOUNT event sent as BYTECOUNT_CLI
			Input:        "BYTECOUNT_CLI:123,456",
			WantErr:      atoiSyntaxErr,
			WantClientId: 123,
			WantBytesIn:  456,
			WantBytesOut: 0,
		},
		{
			Input:        "BYTECOUNT_CLI:",
			WantErr:      atoiSyntaxErr,
			WantClientId: 0,
			WantBytesIn:  0,
			WantBytesOut: 0,
		},
		{
			Input:        "BYTECOUNT_CLI:123,123,456",
			WantErr:      nil,
			WantClientId: 123,
			WantBytesIn:  123,
			WantBytesOut: 456,
		},
		{
			Input:        "BYTECOUNT_CLI:bad,123",
			WantErr:      atoiSyntaxErr2,
			WantClientId: 0,
			WantBytesIn:  0,
			WantBytesOut: 0,
		},
	}

	for i, testCase := range testCases {
		_, kw, body := splitEvent(testCase.Input)
		event := upgradeEvent(kw, body)

		var bc ByteCountClientEvent
		var ok bool
		if testCase.WantErr != nil {
			evt, ok := event.(InvalidEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, event, evt)
				continue
			}

			bc, ok = evt.Origin().(ByteCountClientEvent)
			if !ok {
				t.Errorf("test %d got %T; want %T", i, evt.Origin(), bc)
				continue
			}
			if evt.Error() != testCase.WantErr.Error() {
				t.Errorf("test %d InvalidEvent.Error returned %q; want %q", i, evt.Error(), testCase.WantErr)
				continue
			}
		} else if bc, ok = event.(ByteCountClientEvent); !ok {
			t.Errorf("test %d got %T; want %T", i, event, bc)
			continue
		}

		if got, want := bc.ClientId(), testCase.WantClientId; got != want {
			t.Errorf("test %d ClientId returned %q; want %q", i, got, want)
		}
		if got, want := bc.BytesIn(), testCase.WantBytesIn; got != want {
			t.Errorf("test %d BytesIn returned %d; want %d", i, got, want)
		}
		if got, want := bc.BytesOut(), testCase.WantBytesOut; got != want {
			t.Errorf("test %d BytesOut returned %d; want %d", i, got, want)
		}
	}
}
