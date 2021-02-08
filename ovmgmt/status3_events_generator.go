package ovmgmt

import (
	"time"
)

// SetStatus3Events either enables or disables periodic generation
// of Status3Event.
//
// When enabled, a 'status 3' command will be emitted at given time interval,
// and subsequently Status3Event will be written to event channel.
//
// Set the time interval to zero in order to disable Status3 events.
func (c *MgmtClient) SetStatus3Events(interval time.Duration) bool {
	//logDebugf("stop old generator")
	close(c.doneStatus3Gen)
	if interval > 0 {
		c.doneStatus3Gen = c.status3EventGenerator(interval)
		return true
	} else {
		// logDebugf("bad interval, making new empty chan (old was already closed)")
		c.doneStatus3Gen = make(chan bool, 1)
	}
	return false
}

// LatestStatus3 retrieves generates current Status3Event from the server.
func (c *MgmtClient) LatestStatus3() (*Status3Event, error) {
	err := c.sendCommand("status 3")
	if err != nil {
		return nil, err
	}

	payload, err := c.readCommandResponsePayload()
	if err != nil {
		return nil, err
	}

	s, err := NewStatus3Event(payload)
	return &s, err
}

func (c *MgmtClient) generateStatus3Event() {
	evt, err := c.LatestStatus3()
	if evt != nil && err == nil {
		c.eventSink <- evt
	} else {
		c.eventSink <- NewInvalidEvent(evt, err)
	}
}

func (c *MgmtClient) status3EventGenerator(interval time.Duration) chan bool {
	done := make(chan bool, 1)
	//logDebugf("entering to gen with int %v", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.generateStatus3Event()
			case <-done:
				//logDebugf("exiting from gen with int %v", interval)
				return
			}
		}
	}()
	return done
}
