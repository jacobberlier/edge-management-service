package provider

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.build.ge.com/PredixEdgeOS/management-service/config"
)

//EdgeAgent - struct to contain information related to preforming Edge Agent operations.
type EdgeAgent struct {
	EdgeAgentPort string
	Conf          config.Config
	Proxy         *httputil.ReverseProxy
}

//NewEdgeAgent - Creates a new cappsd provider object to allow for routing to cappsd functions.
func NewEdgeAgent(cfg config.Config) (*EdgeAgent, error) {
	provider := new(EdgeAgent)
	provider.Conf = cfg

	EAConf := cfg.EdgeAgentConf

	str := strings.Join([]string{EAConf.Protocol, "://", EAConf.IP, ":", EAConf.Port}, "")
	log.Infof("enrollment url: %s", str)
	enrollmentURL, err := url.Parse(str)
	if err != nil {
		log.Fatalf("Could not create url for enrollment with provided configuration")
	}

	enrollmentProxy := httputil.NewSingleHostReverseProxy(enrollmentURL)
	if EAConf.UseUnixSocket {
		enrollmentProxy.Transport = &http.Transport{Dial: provider.fakeDial}
	}

	provider.Proxy = enrollmentProxy

	return provider, nil
}

//FakeDial - used to dial the unix socket instead of makeing a rest call.
func (provider *EdgeAgent) fakeDial(proto, addr string) (conn net.Conn, err error) {
	return net.Dial("unix", provider.Conf.EdgeAgentConf.UnixSocketLocation)
}
