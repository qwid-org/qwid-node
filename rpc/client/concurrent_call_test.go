package clientrpc

import (
	"net"
	"net/rpc"
	"testing"
	"time"
)

// fakeListener stands in for the node's RPC server: "SLOW" stalls, anything
// else echoes at once.
type Listener struct{}

func (Listener) Send(line []byte, reply *[]byte) error {
	if string(line) == "SLOW" {
		time.Sleep(2 * time.Second)
	}
	*reply = append([]byte("re:"), line...)
	return nil
}

func startFakeServer(t *testing.T) string {
	t.Helper()
	srv := rpc.NewServer()
	if err := srv.Register(Listener{}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:46926") // isolated test port
	if err != nil {
		t.Skipf("test port busy: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(c)
		}
	}()
	return ln.Addr().String()
}

// S7-02: one slow request must not hold up everyone else's, and no call may
// wait forever.
func TestCallIsConcurrentAndBounded(t *testing.T) {
	addr := startFakeServer(t)
	if err := connectDirect(addr); err != nil {
		t.Fatal(err)
	}
	defer disconnectDirect()

	saved := callTimeout
	callTimeout = 500 * time.Millisecond
	defer func() { callTimeout = saved }()

	slow := make(chan []byte, 1)
	go func() { slow <- Call([]byte("SLOW")) }()
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	if got := string(Call([]byte("FAST"))); got != "re:FAST" {
		t.Fatalf("fast reply = %q", got)
	}
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("a fast call waited %s behind a slow one", el)
	}
	select {
	case got := <-slow:
		if string(got) != "Timeout" {
			t.Fatalf("slow call should time out, got %q", got)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("slow call was not bounded by the timeout")
	}
}
