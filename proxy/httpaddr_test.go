package proxy_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"

	proxytest "github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_HTTPAddrs(t *testing.T) {
	t.Parallel()

	require.NoError(t, proxy.ProtoHTTP.Validate())
	for _, name := range []string{"http_only", "http_and_https"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			httpConf := &proxy.HTTPConfig{InsecureEnabled: true}
			var tlsConf *tls.Config
			if name == "http_and_https" {
				tlsConf, _ = proxytest.NewTLSConfig(t)
				httpConf.ListenAddresses = []netip.AddrPort{proxytest.LocalhostAnyPort}
			}
			p, err := proxy.New(&proxy.Config{
				Logger: testLogger,
				HTTPListenAddr: []*net.TCPAddr{
					net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort),
					net.TCPAddrFromAddrPort(proxytest.LocalhostAnyPort),
				},
				HTTPConfig:     httpConf,
				TLSConfig:      tlsConf,
				UpstreamConfig: newTestUpstreamConfig(t),
			})
			require.NoError(t, err)
			assert.Nil(t, p.Addr(proxy.ProtoHTTP))
			assert.Empty(t, p.Addrs(proxy.ProtoHTTP))
			servicetest.RequireRun(t, p, proxytest.Timeout)

			addrs := p.Addrs(proxy.ProtoHTTP)
			require.Len(t, addrs, 2)
			assert.Equal(t, addrs[0], p.Addr(proxy.ProtoHTTP))
			assert.NotEqual(t, addrs[0], addrs[1])
			if name == "http_and_https" {
				httpsAddr := p.Addr(proxy.ProtoHTTPS)
				require.NotNil(t, httpsAddr)
				assert.NotContains(t, addrs, httpsAddr)
			} else {
				assert.Nil(t, p.Addr(proxy.ProtoHTTPS))
				assert.Empty(t, p.Addrs(proxy.ProtoHTTPS))
			}

			transport := &http.Transport{}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: proxytest.Timeout}
			msg := proxytest.NewTestRequest()
			packed, err := msg.Pack()
			require.NoError(t, err)
			for _, addr := range addrs {
				tcpAddr := testutil.RequireTypeAssert[*net.TCPAddr](t, addr)
				require.Positive(t, tcpAddr.Port)
				resp, respErr := client.Post(
					"http://"+addr.String()+"/dns-query",
					"application/dns-message",
					bytes.NewReader(packed),
				)
				require.NoError(t, respErr)
				testutil.CleanupAndRequireSuccess(t, resp.Body.Close)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				body, readErr := io.ReadAll(resp.Body)
				require.NoError(t, readErr)
				dnsResp := &dns.Msg{}
				require.NoError(t, dnsResp.Unpack(body))
				proxytest.RequireResponse(t, msg, dnsResp)
			}
		})
	}
}
