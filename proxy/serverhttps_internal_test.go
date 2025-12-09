package proxy

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_HTTPListeners_closeOnFail(t *testing.T) {
	t.Parallel()

	occupied, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort))
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, occupied.Close)

	p := mustNew(t, &Config{
		Logger: testLogger,
		HTTPListenAddr: []*net.TCPAddr{
			net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort),
			testutil.RequireTypeAssert[*net.TCPAddr](t, occupied.Addr()),
		},
		HTTPConfig:     &HTTPConfig{InsecureEnabled: true},
		UpstreamConfig: newTestUpstreamConfig(t, newTestUpstream(t)),
	})

	ctx := testutil.ContextWithTimeout(t, dnsproxytest.Timeout)
	require.Error(t, p.initHTTPListeners(ctx))
	require.Len(t, p.httpListen, 1)
	l := p.httpListen[0]
	t.Cleanup(func() {
		// It may already have been closed by the proxy cleanup.
		if closeErr := l.Close(); closeErr != nil {
			require.ErrorIs(t, closeErr, net.ErrClosed)
		}
	})
	addr := testutil.RequireTypeAssert[*net.TCPAddr](t, l.Addr())

	// Start uses this cleanup when listener initialization fails.
	require.Empty(t, p.closeListeners(nil))
	replacement, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err, "the HTTP socket must be released after failed startup")
	testutil.CleanupAndRequireSuccess(t, replacement.Close)
}

func TestProxy_HTTPListeners_immediateShutdown(t *testing.T) {
	// Keep the serving goroutine queued until Shutdown has cleared the server.
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)

	p := mustNew(t, &Config{
		Logger:         testLogger,
		HTTPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		HTTPConfig:     &HTTPConfig{InsecureEnabled: true},
		UpstreamConfig: newTestUpstreamConfig(t, newTestUpstream(t)),
	})
	ctx := testutil.ContextWithTimeout(t, dnsproxytest.Timeout)
	require.NoError(t, p.Start(ctx))
	addr := testutil.RequireTypeAssert[*net.TCPAddr](t, p.httpListen[0].Addr())
	require.NoError(t, p.Shutdown(ctx))
	runtime.Gosched()

	replacement, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err, "the HTTP socket must be released even before Serve runs")
	testutil.CleanupAndRequireSuccess(t, replacement.Close)
}

func TestProxy_HandleDNSRequest_http(t *testing.T) {
	t.Parallel()

	p := mustNew(t, &Config{
		Logger:         testLogger,
		HTTPListenAddr: []*net.TCPAddr{net.TCPAddrFromAddrPort(dnsproxytest.LocalhostAnyPort)},
		HTTPConfig: &HTTPConfig{
			InsecureEnabled: true,
			Routes:          []string{"/custom"},
			Userinfo:        url.UserPassword("user", "password"),
		},
		UpstreamConfig: newTestUpstreamConfig(t, newTestUpstream(t)),
	})
	servicetest.RequireRun(t, p, dnsproxytest.Timeout)

	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: dnsproxytest.Timeout}
	endpoint := "http://" + p.httpListen[0].Addr().String()
	msg := dnsproxytest.NewTestRequest()
	packed, err := msg.Pack()
	require.NoError(t, err)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			u := endpoint + "/custom"
			if method == http.MethodGet {
				u += "?dns=" + base64.RawURLEncoding.EncodeToString(packed)
			}

			req, reqErr := http.NewRequest(method, u, bytes.NewReader(packed))
			require.NoError(t, reqErr)
			req.SetBasicAuth("user", "password")
			req.Header.Set(httphdr.ContentType, "application/dns-message")

			resp, respErr := client.Do(req)
			require.NoError(t, respErr)
			testutil.CleanupAndRequireSuccess(t, resp.Body.Close)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			body, readErr := io.ReadAll(resp.Body)
			require.NoError(t, readErr)
			dnsResp := &dns.Msg{}
			require.NoError(t, dnsResp.Unpack(body))
			dnsproxytest.RequireResponse(t, msg, dnsResp)
		})
	}

	for _, tc := range []struct {
		path string
		want int
	}{
		{path: "/dns-query", want: http.StatusNotFound},
		{path: "/custom", want: http.StatusUnauthorized},
	} {
		resp, respErr := client.Get(endpoint + tc.path)
		require.NoError(t, respErr)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, tc.want, resp.StatusCode)
	}
}

// Common IP address strings for tests.
const (
	testIPStr1 = "192.0.2.1"
	testIPStr2 = "192.0.2.2"
	testIPStr3 = "192.0.2.3"
)

// Common IP adresses for tests.
var (
	testIP1 = netip.MustParseAddr(testIPStr1)
	testIP2 = netip.MustParseAddr(testIPStr2)

	testRaddr = netip.AddrPortFrom(testIP1, 1234)
)

func TestRemoteAddr_direct(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		remoteAddr string
		hdr        http.Header
		wantErr    string
		wantIP     netip.AddrPort
	}{{
		name:       "no_proxy",
		remoteAddr: testRaddr.String(),
		hdr:        nil,
		wantErr:    "",
		wantIP:     testRaddr,
	}, {
		name:       "no_port",
		remoteAddr: testIPStr1,
		hdr:        nil,
		wantErr:    "not an ip:port",
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_port",
		remoteAddr: testIPStr1 + ":notport",
		hdr:        nil,
		wantErr:    `invalid port "notport" parsing "` + testIPStr1 + `:notport"`,
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_host",
		remoteAddr: "host:1",
		hdr:        nil,
		wantErr:    `ParseAddr("host"): unable to parse IP`,
		wantIP:     netip.AddrPort{},
	}, {
		name:       "bad_proxied_host",
		remoteAddr: "host:1",
		hdr: http.Header{
			httphdr.CFConnectingIP: []string{testIPStr1},
		},
		wantErr: `ParseAddr("host"): unable to parse IP`,
		wantIP:  netip.AddrPort{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testRemoteAddr(t, tc.remoteAddr, tc.hdr, tc.wantErr, tc.wantIP, netip.AddrPort{})
		})
	}
}

// testRemoteAddr makes sure that remoteAddr returns expected IP and proxy for
// given raddr and header.
func testRemoteAddr(
	tb testing.TB,
	raddr string,
	header http.Header,
	wantErrMsg string,
	wantIP netip.AddrPort,
	wantProxy netip.AddrPort,
) {
	r, err := http.NewRequest(http.MethodGet, dnsproxytest.Host, nil)
	require.NoError(tb, err)

	r.RemoteAddr = raddr
	r.Header = header

	var addr, prx netip.AddrPort
	addr, prx, err = remoteAddr(r, testLogger)
	if wantErrMsg != "" {
		testutil.AssertErrorMsg(tb, wantErrMsg, err)

		return
	}

	require.NoError(tb, err)
	assert.Equal(tb, wantIP, addr)
	assert.Equal(tb, wantProxy, prx)
}

func TestRemoteAddr_proxied(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		remoteAddr string
		hdr        http.Header
		wantErr    string
		wantIP     netip.AddrPort
		wantProxy  netip.AddrPort
	}{{
		name:       "proxied_with_cloudflare",
		remoteAddr: testRaddr.String(),
		hdr: http.Header{
			httphdr.CFConnectingIP: []string{testIPStr2},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}, {
		name:       "proxied_once",
		remoteAddr: testRaddr.String(),
		hdr: http.Header{
			httphdr.XForwardedFor: []string{testIPStr2},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}, {
		name:       "proxied_multiple",
		remoteAddr: testRaddr.String(),
		hdr: http.Header{
			httphdr.XForwardedFor: []string{testIPStr2 + "," + testIPStr3},
		},
		wantErr:   "",
		wantIP:    netip.AddrPortFrom(testIP2, 0),
		wantProxy: testRaddr,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testRemoteAddr(t, tc.remoteAddr, tc.hdr, tc.wantErr, tc.wantIP, tc.wantProxy)
		})
	}
}
