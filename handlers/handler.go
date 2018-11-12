package handlers

import (
	"go.uber.org/zap"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.build.ge.com/PredixEdgeOS/management-service/config"
	"github.build.ge.com/PredixEdgeOS/management-service/provider"
	"github.com/gorilla/mux"
)

var zapstd, _ = zap.NewProduction()
var log = zapstd.Sugar()

type basicResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

func createRouter(cfg config.Config) *mux.Router {
	cappsd, err := provider.NewCappsd(cfg)
	if err != nil {
		log.Fatalf("Could not create Cappsd provider:\n%s", err)
	}
	dbus, err := provider.NewDBus(cfg)
	if err != nil {
		log.Fatalf("Could not create DBus provider:\n%s", err)
	}
	edgeAgent, err := provider.NewEdgeAgent(cfg)
	if err != nil {
		log.Fatalf("Could not create the Edge Agnet provider:\n%s", err)
	}

	router := mux.NewRouter()

	//cappsd endpoints, container management proxy
	router.HandleFunc("/applications", cappsd.Proxy).Methods("GET")
	router.HandleFunc("/applications/ping", cappsd.Proxy).Methods("GET")
	router.HandleFunc("/application/deploy", cappsd.Proxy).Methods("POST")
	router.HandleFunc("/application/details/{id}", cappsd.Proxy).Methods("GET")
	router.HandleFunc("/application/status/{id}", cappsd.Proxy).Methods("GET")
	router.HandleFunc("/application/restart/{id}", cappsd.Proxy).Methods("POST")
	router.HandleFunc("/application/start/{id}", cappsd.Proxy).Methods("POST")
	router.HandleFunc("/application/stop/{id}", cappsd.Proxy).Methods("POST")
	router.HandleFunc("/application/purge/{id}", cappsd.Proxy).Methods("POST")
	router.HandleFunc("/application/kill/{id}", cappsd.Proxy).Methods("POST")

	//cappsd endpoints, new format, still just a proxy to unix socket
	router.HandleFunc("/api/v1/containers", cappsd.Proxy).Methods("GET")
	router.HandleFunc("/api/v1/containers/ping", cappsd.Proxy).Methods("GET")
	router.HandleFunc("/api/v1/containers/instances", cappsd.Proxy).Methods("POST")
	router.HandleFunc("/api/v1/containers/instances/{instanceId}/{command}", cappsd.Proxy).Methods("POST", "GET")

	//Network configuration endpoints
	router.HandleFunc("/api/v1/host/network/interfaces", dbus.GetNetworkConfig).Methods("GET")
	router.HandleFunc("/api/v1/host/network/interfaces/{interface}", dbus.GetNetworkConfig).Methods("GET")
	router.HandleFunc("/api/v1/host/network/interfaces/{interface}/{setMethod}", dbus.ConfigureNetwork).Methods("PUT")
	router.HandleFunc("/api/v1/host/network/ntp", dbus.GetNTP).Methods("GET")
	router.HandleFunc("/api/v1/host/network/ntp", dbus.SetNTP).Methods("PUT")
	router.HandleFunc("/api/v1/host/network/proxy", dbus.GetProxy).Methods("GET")
	router.HandleFunc("/api/v1/host/network/proxy", dbus.SetProxy).Methods("PUT")

	//OS specific endpoints, host update, os version
	router.HandleFunc("/api/v1/host/update", dbus.Update).Methods("POST")
	router.HandleFunc("/api/v1/host/state", dbus.UpdateStatus).Methods("GET")
	router.HandleFunc("/api/v1/host/version", dbus.Version).Methods("GET")

	// logs endpoints, log sources, logs from supplied source
	router.HandleFunc("/api/v1/host/logs/sources", dbus.LogSources).Methods("GET")
	router.HandleFunc("/api/v1/host/logs/{type}/{source}", dbus.Logs).Methods("GET", "DELETE")

	//TODO: enroll and unenroll
	//router.HandleFunc("/api/v1/host/unenroll", dbus.Enroll).Methods("GET")
	//router.HandleFunc("/api/v1/host/enroll", dbus.Enroll).Methods("POST", "PUT")
	router.HandleFunc("/api/v1/host/enroll", edgeAgent.Proxy.ServeHTTP).Methods("POST", "PUT")

	//docker proxy configuration, Get/Set
	router.HandleFunc("/api/v1/host/dockerproxy", dbus.GetDockerProxy).Methods("GET")
	router.HandleFunc("/api/v1/host/dockerproxy", dbus.SetDockerProxy).Methods("POST")

	//Reboot via dbus
	router.HandleFunc("/reboot", dbus.Reboot).Methods("POST")

	//Retrieve Hosts
	router.HandleFunc("/hosts", dbus.GetHosts).Methods("GET")
	router.HandleFunc("/hosts", dbus.SetHosts).Methods("POST")

	//Manage IP Address Whitelist
	router.HandleFunc("/whitelist/start", dbus.StartWhitelist).Methods("POST")
	router.HandleFunc("/whitelist/stop", dbus.StopWhitelist).Methods("POST")

	//Manage SSH Access
	router.HandleFunc("/ssh/status", dbus.StatusSSH).Methods("GET")
	router.HandleFunc("/ssh/enable", dbus.EnableSSH).Methods("POST")
	router.HandleFunc("/ssh/disable", dbus.DisableSSH).Methods("POST")

	//Manage Metrics Metrics
	router.HandleFunc("/metrics/cpu", dbus.CPUMetrics).Methods("GET")
	router.HandleFunc("/metrics/mem", dbus.MemMetrics).Methods("GET")
	router.HandleFunc("/metrics/disk", dbus.DiskMetrics).Methods("GET")
	router.HandleFunc("/metrics/net", dbus.NetMetrics).Methods("GET")

	return router
}

func setupTCPServer(cfg config.Config, router *mux.Router) *http.Server {
	listenAddr := cfg.ListenAddress
	//should remove the need for the colon on the port number in the config.
	if !strings.HasPrefix(listenAddr, ":") {
		listenAddr = strings.Join([]string{":", listenAddr}, "")
	}
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
	}

	return server
}

func setupUdsServer(cfg config.Config, router *mux.Router) *http.Server {
	err := syscall.Unlink(cfg.UnixSocketPath)
	if nil != err {
		log.Warnf("Failed to unlink Unix Socket (%s); ignoring as this is intended to remove dangling sockets and such a socket might not exist: %s\n", cfg.UnixSocketPath, err)
	}

	server := &http.Server{
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
	}

	return server
}

func startServer(server *http.Server, cfg config.Config, domainSocket bool, ch chan string) {
	if domainSocket {
		unixListener, err := net.Listen("unix", cfg.UnixSocketPath)
		if nil == err {
			server.Serve(unixListener)
		} else {
			log.Errorf("Unable to start UDS server: %s", err)
		}
	} else {
		if cfg.TLS {
			cert := cfg.Cert
			key := cfg.Key
			err := server.ListenAndServeTLS(cert, key)
			if nil == err {
				log.Errorf("Unable to start TLS TCP server: %s", err)
			}
		} else {
			err := server.ListenAndServe()
			if nil == err {
				log.Errorf("Unable to start non-TLS TCP server: %s", err)
			}
		}
	}
	if nil != ch {
		log.Infof("Notifying of system shutdown...")
		ch <- "done"
	}
}

//Start - creates the http/https server where the management service api is hosted
func Start(cfg config.Config) {
	router := createRouter(cfg)
	tcpServer := setupTCPServer(cfg, router)
	udsServer := setupUdsServer(cfg, router)
	udsChannel := make(chan string)
	if cfg.RemoteManagement {
		log.Infof("Starting TCP server...")
		go startServer(tcpServer, cfg, false, nil)
	}
	log.Infof("Starting UDS server...")
	go startServer(udsServer, cfg, true, udsChannel)
	select {
	case <-udsChannel:
		log.Infof("Shutting down...")
	}
}
