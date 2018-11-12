package provider

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/godbus/dbus"
	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.build.ge.com/PredixEdgeOS/management-service/config"
)

const _systemdBaseName string = "org.freedesktop.systemd1"
const _systemdObjectPath string = "/org/freedesktop/systemd1"

var zapstd, _ = zap.NewProduction()
var log = zapstd.Sugar()

type basicDBusResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

type loggingResponse struct {
	Status string `json:"status"`
	Logs   string `json:"logs"`
}

type _logSources struct {
	Services   []string `json:"services"`
	Containers []string `json:"containers"`
}

type currentNetworkConfig struct {
	resp string
}

//NetInfo - struct that contains network configuration information
type NetInfo struct {
	DNS     string `json:"dns"`
	IP      string `json:"ipv4"`
	Gateway string `json:"gateway"`
}

type oldNetInfo struct {
	Name    string `json:"name"`
	DNS     string `json:"dns"`
	Dhcp    bool   `json:"dhcp"`
	IP      string `json:"ipv4"`
	Gateway string `json:"gateway"`
}
type _ipv6 struct {
	B1  []byte
	Num uint32
	B2  []byte
}

type _ipv6Routes struct {
	B1   []byte
	Num  uint32
	B2   []byte
	Num2 uint32
}

type _DNS struct {
	Primary   string `json:"primary"`
	Secondary string `json:"secondary"`
}

type _NTP struct {
	NTP      string `json:"ntp"`
	Fallback string `json:"fallback"`
}

type _Proxy struct {
	HTTPProxy  string `json:"http_proxy"`
	HTTPSProxy string `json:"https_proxy"`
	NoProxy    string `json:"no_proxy"`
}

type _VER struct {
	Status  string `json:"status"`
	Error   string `json:"error"`
	Version string `json:"version"`
}

type _Whitelist struct {
	ContainerName string   `json:"container_name"`
	WhitelistIPs  []string `json:"whitelist_ips"`
}

type _SSH struct {
	IPAddress string `json:"ip_address"`
	SSHPubKey string `json:"ssh_pub_key"`
}

type _Host struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

type _HostDBus struct {
	IP    string   `json:"ip"`
	Hosts []string `json:"hosts"`
}

type _CPUStats struct {
	LoadAverages    []float64 `json:"load_averages"`
	NumRunningProcs uint64    `json:"num_running_procs"`
	Usage           float32   `json:"usage"`
	UserCycles      uint64    `json:"user_cycles"`
	NiceCycles      uint64    `json:"nice_cycles"`
	SystemCycles    uint64    `json:"system_cycles"`
	IdleCycles      uint64    `json:"idle_cycles"`
	IOWaitCycles    uint64    `json:"io_wait_cycles"`
	TotalCycles     uint64    `json:"total_cycles"`
}

type _DiskStats struct {
	TotalReads  uint64 `json:"total_reads"`
	TotalWrites uint64 `json:"total_writes"`
}

type _NetStats struct {
	TotalRx uint64 `json:"total_rx"`
	TotalTx uint64 `json:"total_tx"`
}

type _MemStats struct {
	MemFree uint64 `json:"mem_free"`
}

//DBus - DBus provider struct contains refs to dbus connections.
type DBus struct {
	Bus    *dbus.Conn
	Port   string
	Lock   sync.RWMutex
	Conf   config.Config
	Client *http.Client
}

//NewDBus - function to initialize a DBus provider object
func NewDBus(cfg config.Config) (*DBus, error) {
	provider := new(DBus)
	provider.init(cfg)
	return provider, nil
}

//Init - initializes a dbus object
func (provider *DBus) init(cfg config.Config) {
	provider.Conf = cfg
	provider.Port = cfg.DBusPort
	//init the connection to the dbus interface on localhost
	con, err := dbus.SystemBus()

	if err != nil {
		//An error has occured
		log.Fatal(err)
	}
	//Con is an initialize connection to the DBus interface
	//assign this connection to ensure we use the same one for multiple calls
	provider.Bus = con
}

//FakeDial - used to dial the unix socket instead of makeing a rest call.
func (provider *DBus) FakeDial(proto, addr string) (conn net.Conn, err error) {
	return net.Dial("unix", provider.Conf.EdgeAgentConf.UnixSocketLocation)
}

//ParseProxyString - This function allows easy parsing of the proxy environment variables.
func ParseProxyString(discoveredString string, prefix string) string {
	// Remove any newlines or quote marks.
	editedString := strings.Replace(discoveredString, "\n", "", 2)
	editedString = strings.Replace(editedString, "\"", "", 2)
	// Remove label. Prep for coversion to JSON.
	formattedString := strings.TrimPrefix(editedString, prefix)
	return formattedString
}

//LogSources - get sources of logs.
func (provider *DBus) LogSources(w http.ResponseWriter, r *http.Request) {
	//list of services could be a static list.
	services := []string{"kernel", "systemd"}
	log.Infof("Known services, %v", services)
	//to get the running container uuids. docker ps -q
	//uuids may not be helpful as cappsd is the one creating the uuids not docker??
	output, err := exec.Command("sh", "-c", "docker ps -q").Output()
	if err != nil {
		log.Errorf("Could not get running docker containers: %v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	containers := removeEmptyStrings(strings.Split(string(output), "\n"))
	log.Infof("Available Containers: %v", containers)

	json.NewEncoder(w).Encode(_logSources{Services: services, Containers: containers})
}

//Logs - Handles both Get and Clear systemd logs.
func (provider *DBus) Logs(w http.ResponseWriter, r *http.Request) {
	//stubb
	switch r.Method {
	case "DELETE":
		clearLogs(w, r)
	case "GET":
		getLogs(w, r)
	default:
		handle("Bad Request", http.StatusBadRequest, w)
	}
}

func clearLogs(w http.ResponseWriter, r *http.Request) {
	//clear the logs
	var output []byte
	var err error

	output, err = exec.Command("journalctl", "--flush", "--rotate").Output()
	if err != nil {
		handle(err.Error(), http.StatusInternalServerError, w)
	}
	output, err = exec.Command("journalctl", "--vacuum-time=1s").Output()
	if err != nil {
		handle(err.Error(), http.StatusInternalServerError, w)
	}
	response := loggingResponse{Status: "OK", Logs: string(output)}
	json.NewEncoder(w).Encode(response)
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	//get logs of type vars['type'] from source vars['source']
	var output []byte
	var err error
	var statusCode = http.StatusInternalServerError
	vars := mux.Vars(r)
	switch vars["type"] {
	case "services":
		switch vars["source"] {
		case "systemd":
			//journalctl
			output, err = exec.Command("sh", "-c", "journalctl").Output()
		case "kernel":
			//journalctl -k
			output, err = exec.Command("journalctl", "-k").Output()
		}
	case "containers":
		//docker logs
		output, err = exec.Command("sh", "-c", "docker", "logs", vars["source"]).Output()
	default:
		output = nil
		err = errors.New("could not determine type of logs to get")
	}
	if err != nil {
		handle(err.Error(), statusCode, w)
		return
	}
	response := loggingResponse{Status: "OK", Logs: string(output)}
	json.NewEncoder(w).Encode(response)
}

//Reboot - reboot device using dbus
func (provider *DBus) Reboot(w http.ResponseWriter, r *http.Request) {
	log.Infof("Reboot requested")
	if !provider.Conf.AllowReboot {
		// return error here, Reboot not allowed.
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(basicDBusResponse{Status: "Failed", Error: "Not Allowed, cannot preform reboot"})
		return
	}

	//else reboot using dbus.
	rootObj := provider.Bus.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	log.Infof("DBus Object created")
	log.Infof("Destination: %s", rootObj.Destination())
	log.Infof("Path: %s", rootObj.Path())

	call := rootObj.Call("org.freedesktop.login1.Manager.Reboot", 0, false)

	log.Infof("Call made, checking results")
	if call.Err != nil {
		log.Errorf("Could not preform call to reboot, %v", call.Err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(basicDBusResponse{Status: "Failed", Error: call.Err.Error()})
		return
	}
	log.Infof("Call made, OS should be rebooting, and you should not see this message")
	//Should never get here, but put somehting for success just incase it takes a minute to run reboot.
	json.NewEncoder(w).Encode(basicDBusResponse{Status: "OK", Error: ""})
	return
}

//ConfigureNetwork - Configure the NetworkManager via DBus interface (Manually)
func (provider *DBus) ConfigureNetwork(w http.ResponseWriter, r *http.Request) {
	//TODO: add support for adding network device/connection configuration if they do not exist.
	decoder := json.NewDecoder(r.Body)
	resp := basicDBusResponse{Status: "OK", Error: ""}
	var t NetInfo
	err := decoder.Decode(&t)
	if err != nil {
		log.Errorf("Could not proccess request body:\n%v", err)
		resp.Status = "FAIL"
		resp.Error = err.Error()
		json.NewEncoder(w).Encode(resp)
		return
	}

	vars := mux.Vars(r)

	rootObj := provider.Bus.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
	var devicePath string
	err = rootObj.Call("org.freedesktop.NetworkManager.GetDeviceByIpIface", 0, vars["interface"]).Store(&devicePath)
	if err != nil {
		log.Errorf("Could not get device with name: %v", vars["interface"])
		log.Errorf("Error: %v", err)
		resp.Status = "FAIL"
		resp.Error = err.Error()
		json.NewEncoder(w).Encode(resp)
		return
	}

	deviceObj := provider.Bus.Object("org.freedesktop.NetworkManager", dbus.ObjectPath(devicePath))
	activeConnPath, err := deviceObj.GetProperty("org.freedesktop.NetworkManager.Device.ActiveConnection")
	if err != nil {
		log.Error("Could not get active connection property of interface:\n%v", err)
		resp.Status = "FAIL"
		resp.Error = err.Error()
		json.NewEncoder(w).Encode(resp)
		return
	}

	acObj := provider.Bus.Object("org.freedesktop.NetworkManager", activeConnPath.Value().(dbus.ObjectPath))
	connPath, err := acObj.GetProperty("org.freedesktop.NetworkManager.Connection.Active.Connection")
	if err != nil {
		log.Errorf("Could not get connection property.\n%v", err)
		resp.Status = "FAIL"
		resp.Error = err.Error()
		json.NewEncoder(w).Encode(resp)
		return
	}
	conSettings := provider.Bus.Object("org.freedesktop.NetworkManager", connPath.Value().(dbus.ObjectPath))

	var settings map[string]map[string]dbus.Variant
	err = conSettings.Call("org.freedesktop.NetworkManager.Settings.Connection.GetSettings", 0).Store(&settings)
	if err != nil {
		log.Errorf("Could not get settings,\n%v", err)
		resp.Status = "FAIL"
		resp.Error = err.Error()
		json.NewEncoder(w).Encode(resp)
		return
	}
	ipv4 := settings["ipv4"]

	if vars["setMethod"] == "dhcp" {
		ipv4["method"] = dbus.MakeVariant("auto")
	} else if vars["setMethod"] == "manual" {
		var ip = t.IP
		if len(ip) <= 0 {
			//Fail since Ip cannot be the same
			handle("No Ip address supplied", http.StatusBadRequest, w)
			return
		}
		uip, subnetMask, err := provider.ipToInt(ip)
		if err != nil {
			log.Errorf("Could not convert ip to uint32: %v", err)
			resp.Status = "FAIL"
			resp.Error = err.Error()
			json.NewEncoder(w).Encode(resp)
			return
		}
		//use ip to int to convert the gateway into a uint32, as dbus is expecting that.
		var ugateway uint32
		if len(t.Gateway) > 0 {
			ugateway, _, err = provider.ipToInt(t.Gateway)
			if err != nil {
				log.Errorf("Could not parse gateway into uint32: %v", err)
				handle("Invalid Gateway supplied", http.StatusBadRequest, w)
				return
			}
		} else {
			ugateway = 0
		}

		var uDNS []uint32
		//convert dns ip into a uint32
		if len(t.DNS) > 0 {
			uDNS, err = provider.dnsToInt(t.DNS)
			if err != nil {
				log.Errorf("Could not convert DNS ip to uint32: %v", err)
				handle("Invalid DNS supplied", http.StatusBadRequest, w)
				return
			}
		} else {
			uDNS = []uint32{0}
		}
		log.Info("Initial dns settings: ", ipv4["dns"])
		log.Infof("uDNS = %v", uDNS)
		ipv4["method"] = dbus.MakeVariant("manual")
		ipv4["addresses"] = dbus.MakeVariant([][]uint32{[]uint32{uip, subnetMask, ugateway}})
		ipv4["address-data"] = dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant(ip), "prefix": dbus.MakeVariant(subnetMask)}})
		ipv4["dns"] = dbus.MakeVariant(uDNS)
	} else {
		handle("Invalid set configuration method, available options: manual, dhcp", http.StatusBadRequest, w)
		return
	}

	//TODO: enable the configuration of ipv6 settings
	//NOTE: these ipv6 setting need to be set, but are being set to nothing, dbus complains if these values are not present in the dbus request.
	ipv6 := settings["ipv6"]
	ipv6["addresses"] = dbus.MakeVariant([]_ipv6{{B1: []byte("localhost"), B2: []byte("localhost"), Num: 0}})
	ipv6["routes"] = dbus.MakeVariant([]_ipv6Routes{{B1: []byte("nothing"), B2: []byte("nothing"), Num: 0, Num2: 0}})

	//send back a 201,
	log.Infof("Responding with 201")
	resp.Status = "OK"
	resp.Error = ""
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
	go update(settings, conSettings, deviceObj, rootObj, connPath, devicePath)
	return
}
func update(settings map[string]map[string]dbus.Variant, conSettings dbus.BusObject, deviceObj dbus.BusObject, rootObj dbus.BusObject, connPath dbus.Variant, devicePath string) {

	call := conSettings.Call("org.freedesktop.NetworkManager.Settings.Connection.Update", 0, settings)
	if call.Err != nil {
		log.Errorf("Call received error: %v", call.Err)
		return
	}

	//reset the device to get the new config.
	//disconnect device then up the connection
	call = deviceObj.Call("org.freedesktop.NetworkManager.Device.Disconnect", 0)
	if call.Err != nil {
		log.Errorf("could not disconnect device: %v", call.Err)
		return
	}
	var ac dbus.ObjectPath
	//TODO: may need to use specific obj here (last param), if modifying VPN connections as per the dbus documentation
	err := rootObj.Call("org.freedesktop.NetworkManager.ActivateConnection", 0, connPath.Value().(dbus.ObjectPath), dbus.ObjectPath(devicePath), dbus.ObjectPath("/")).Store(&ac)
	if err != nil {
		log.Errorf("Could not reactivate connection: %v", err)
		return
	}
	return
}

func (provider *DBus) dnsToInt(dns string) ([]uint32, error) {
	regex := regexp.MustCompile("^(((1\\d?\\d?|2[0-4]\\d|25[0-5]|\\d\\d?)\\.){3}(1\\d?\\d?|2[0-4]\\d|25[0-5]|\\d\\d?)(\\,|$))*")
	if !regex.MatchString(dns) {
		return []uint32{0}, errors.New("Non valid dns list supplied")
	}
	var dnsList []uint32
	strList := strings.Split(dns, ",")
	//return []uint32{0}, errors.New("Not implemented")
	for _, ele := range strList {
		if ele == "" {
			continue
		} else {
			//attempt to parse into a uint32
			num, _, err := provider.ipToInt(ele)
			if err != nil {
				return []uint32{0}, err
			}
			dnsList = append(dnsList, num)
		}
	}
	return dnsList, nil
}

func revIPAddr(ipaddress string) (string, error) {
	chunk := strings.Split(ipaddress, ".")
	if len(chunk) < 4 {
		return ipaddress, errors.New("Supplied IP address is not valid")
	}
	var otherChunk = make([]string, 4, 4)
	otherChunk[0] = chunk[3]
	otherChunk[1] = chunk[2]
	otherChunk[2] = chunk[1]
	otherChunk[3] = chunk[0]

	return strings.Join(otherChunk, "."), nil
}

//returns, ip, subnetMask, errors
func (provider *DBus) ipToInt(ipaddress string) (uint32, uint32, error) {

	//match on both w.x.y.z/q and w.x.y.z
	regex := regexp.MustCompile("\\d{1,3}(\\.\\d{1,3}){3}(\\/\\d{1,2})?")
	if !regex.MatchString(ipaddress) {
		return 0, 0, errors.New("ip address received is not a valid ip address")
	}
	var chunk []string
	var subnet uint32
	ip := strings.Split(ipaddress, "/")
	if len(ip) > 1 {
		// ip is of the form w.x.y.z/q
		s, err := strconv.Atoi(ip[1])
		if err != nil {
			return 0, 0, err
		}
		subnet = uint32(s)
	} else {
		//ip is of the form w.x.y.z
		if len(ip) < 1 {
			//there is no ip, should never get here
			return 0, 0, errors.New("Invalid Ip")
		}
		subnet = uint32(provider.Conf.NetworkConf.SubnetDefault)
	}

	addr, err := revIPAddr(ip[0])
	if err != nil {
		return 0, 0, err
	}
	chunk = strings.Split(addr, ".")

	var sum uint32
	if len(chunk) > 3 {
		char, _ := strconv.Atoi(chunk[0])
		sum += uint32(char) << 24
		char, _ = strconv.Atoi(chunk[1])
		sum += uint32(char) << 16
		char, _ = strconv.Atoi(chunk[2])
		sum += uint32(char) << 8
		char, _ = strconv.Atoi(chunk[3])
		sum += uint32(char)
	}
	return sum, subnet, nil
}

//GetNetworkConfig - Returns information about the network configuration reported by the NetworkManager DBus interface
func (provider *DBus) GetNetworkConfig(w http.ResponseWriter, r *http.Request) {
	var netConfigList []oldNetInfo

	conn, err := dbus.SystemBus()
	if err != nil {
		panic(err)
	}
	obj := conn.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
	devices, _ := obj.GetProperty("org.freedesktop.NetworkManager.Devices")
	activeDevices := devices.Value().([]dbus.ObjectPath)

	for _, active := range activeDevices {
		obj2 := conn.Object("org.freedesktop.NetworkManager", active)

		props21, _ := obj2.GetProperty("org.freedesktop.NetworkManager.Device.Ip4Config")
		props22, _ := obj2.GetProperty("org.freedesktop.NetworkManager.Device.Dhcp4Config")
		deviceInterface, _ := obj2.GetProperty("org.freedesktop.NetworkManager.Device.Interface")

		ip4ObjectPath := props21.Value().(dbus.ObjectPath)
		dhcpObjectPath := props22.Value().(dbus.ObjectPath)

		obj3 := conn.Object("org.freedesktop.NetworkManager", ip4ObjectPath)
		//IP4Config contains dns information. Domains, DnsOptions, DnsPriorityc
		addressData, _ := obj3.GetProperty("org.freedesktop.NetworkManager.IP4Config.AddressData")
		ip4AddressSlice := []string{}
		if p, ok := addressData.Value().([]map[string]dbus.Variant); ok {
			addressMaps := p
			for _, addressMap := range addressMaps {
				//log.Info("ipv4 addressMap = ", addressMap)
				ip4Address := ""
				if n, ok := addressMap["address"].Value().(string); ok {
					ip4Address = n
				} else {
					continue
				}
				if len(ip4Address) > 0 {
					ip4AddressSlice = append(ip4AddressSlice, ip4Address)
				}
			}
		} else {
			continue
		}
		gateway, _ := obj3.GetProperty("org.freedesktop.NetworkManager.IP4Config.Gateway")
		dns, _ := obj3.GetProperty("org.freedesktop.NetworkManager.IP4Config.Nameservers")
		obj32 := conn.Object("org.freedesktop.NetworkManager", dhcpObjectPath)
		dhcpOptions, _ := obj32.GetProperty("org.freedesktop.NetworkManager.DHCP4Config.Options")

		dhcpServer := ""
		dhcp := false
		if dhcpOptions.Value() != nil {
			dhcpMap := dhcpOptions.Value().(map[string]dbus.Variant)
			if dhcpMap != nil {
				dhcpServer = ""
				if n, ok := dhcpMap["dhcpServer_identifier"].Value().(string); ok {
					dhcpServer = n
				}
			}
			dhcp = (dhcpServer != "")
		}
		var newDNSList []string
		if len(dns.Value().([]uint32)) > 0 {
			for _, element := range dns.Value().([]uint32) {
				str, err := int2IP(element)
				if err != nil {
					log.Errorf("could not convert ip to string: %s", err.Error())
					//Not a critical error.
					continue
				}
				newDNSList = append(newDNSList, str)
			}
		} else {
			newDNSList = []string{}
		}

		config := oldNetInfo{
			Dhcp: dhcp,
			DNS:  strings.Join(newDNSList, ","),
			IP:   strings.Join(ip4AddressSlice, ",")}
		if g, ok := gateway.Value().(string); ok {
			config.Gateway = g
		} else {
			config.Gateway = ""
		}
		if g, ok := deviceInterface.Value().(string); ok {
			config.Name = g
		} else {
			config.Name = ""
		}
		if strings.Contains(config.Name, "eth") || strings.Contains(config.Name, "en") || strings.Contains(config.Name, "wl") || strings.Contains(config.Name, "ww") {
			netConfigList = append(netConfigList, config)
		} else {
			continue
		}

	}
	log.Infof("Sending configuration list: %v", netConfigList)

	json.NewEncoder(w).Encode(netConfigList)
}

func int2IP(num uint32) (string, error) {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, num)
	addr, err := revIPAddr(ip.String())
	if err != nil {
		return "", err
	}
	return addr, nil
}

//SetNTP - set NTP settings mock
func (provider *DBus) SetNTP(w http.ResponseWriter, r *http.Request) {
	//fetch the request body
	decoder := json.NewDecoder(r.Body)

	var t _NTP
	err := decoder.Decode(&t)
	if err != nil {
		log.Errorf("Could not process request body: %v", err)
		handle("Could not process request body", http.StatusBadRequest, w)
		return
	}
	//text of conf file, for easy file contents replacement.
	confText := "[Time]\nNTP=REP1\nFallbackNTP=REP2"
	ntpFileLocation := provider.Conf.NTPConf
	regex, err := regexp.Compile("(.*\\.com|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|.*\\.org)\\s?(.*\\.com|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|.*\\.org)*\\s?")
	if err != nil {
		log.Errorf("Could not compile regex: %v", err)
		handle("Internal Server Error", http.StatusInternalServerError, w)
		return
	}
	if regex.MatchString(t.NTP) || t.NTP == "" {
		confText = strings.Replace(confText, "REP1", t.NTP, -1)
	}
	if regex.MatchString(t.Fallback) || t.Fallback == "" {
		confText = strings.Replace(confText, "REP2", t.Fallback, -1)
	}

	err = ioutil.WriteFile(ntpFileLocation, []byte(confText), 0666)
	if err != nil {
		log.Errorf("Could write to ntp config: %v", err)
		handle("Could write to ntp config", http.StatusInternalServerError, w)
		return
	}

	obj := provider.Bus.Object(_systemdBaseName, dbus.ObjectPath(_systemdObjectPath))
	call := obj.Call("org.freedesktop.systemd1.Manager.RestartUnit", 0, "systemd-timesyncd.service", "replace")
	if call.Err != nil {
		log.Errorf("Could not restart timesyncd: %v", call.Err)
		handle("Could not restart timesyncd", http.StatusInternalServerError, w)
		return
	}

	b, err := json.Marshal(basicDBusResponse{Status: "OK", Error: ""})
	json.NewEncoder(w).Encode(string(b))
}

//GetNTP - get NTP settings mock
func (provider *DBus) GetNTP(w http.ResponseWriter, r *http.Request) {
	var t _NTP
	ntp := ""
	fallback := ""
	ntpConfigLocation := provider.Conf.NTPConf
	//create a scanner to read the file as a set of lines
	input, err := ioutil.ReadFile(ntpConfigLocation)
	if err != nil {
		log.Errorf("Could not read ntp configuration: %v", err)
		handle("Could not read ntp configuration", http.StatusInternalServerError, w)
		return
	}
	lines := strings.Split(string(input), "\n")
	for _, line := range lines {
		if strings.Contains(line, "FallbackNTP") {
			split := strings.Split(line, "=")
			if len(split) > 1 {
				fallback = split[1]
			} else {
				fallback = ""
			}
		} else if strings.Contains(line, "NTP") {
			split := strings.Split(line, "=")
			if len(split) > 1 {
				ntp = split[1]
			} else {
				ntp = ""
			}
		}
	}

	t = _NTP{NTP: ntp, Fallback: fallback}
	json.NewEncoder(w).Encode(t)
}

//SetProxy - set the proxy settings using a JSON format.
func (provider *DBus) SetProxy(w http.ResponseWriter, r *http.Request) {
	log.Info("[Set-Proxy] set proxy detected!")
	// Get the Proxy settings from the request.
	decoder := json.NewDecoder(r.Body)

	var t _Proxy
	err := decoder.Decode(&t)
	if err != nil {
		log.Errorf("Could not parse request body:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}

	var path = provider.Conf.EnvFile
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("[Set-Proxy] file doesn't exist!")
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	proxyString := "http_proxy=%s\nhttps_proxy=%s\nno_proxy=%s"
	// TODO: Add handling for when file is already populated.
	proxyString = fmt.Sprintf(proxyString, t.HTTPProxy, t.HTTPSProxy, t.NoProxy)
	err = ioutil.WriteFile(path, []byte(proxyString), 0644)
	if err != nil {
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	// Send back the response.
	response := basicDBusResponse{Status: "OK", Error: ""}
	json.NewEncoder(w).Encode(response)
}

//GetProxy - Get current proxy settings mock.
func (provider *DBus) GetProxy(w http.ResponseWriter, r *http.Request) {
	log.Info("[Get-Proxy] get proxy detected!")
	var path = provider.Conf.EnvFile
	file, err := ioutil.ReadFile(path)
	if err != nil {
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	fileString := string(file)

	// Check for empty proxy file.
	if fileString == "" || fileString == "\n" {
		// Current Assumption is that this file is only proxies.
		// TODO: Change to get proxy variables from the shell and alter the GO processes.
		log.Info("[Get-Proxy] unable to get proxy. Empty file found.")
		response := basicDBusResponse{Status: "OK", Error: "EMPTY"}
		json.NewEncoder(w).Encode(response)
		return
	}
	// Form each regex to test against.
	proxyRegex := regexp.MustCompile("http_proxy[=][a-zA-Z0-9:\\/\\.]*\nhttps_proxy=[a-zA-Z0-9:\\/\\.]*\nno_proxy=[a-zA-Z0-9:\\/\\.]*[\n]?")
	// Test string against each regex.
	match := proxyRegex.MatchString(fileString)
	if !match {
		handle("/etc/environment is in an improper format.", http.StatusInternalServerError, w)
		return
	}
	parts := strings.Split(fileString, "\n")
	if len(parts) != 3 {
		proxyData := _Proxy{HTTPProxy: "", HTTPSProxy: "", NoProxy: ""}
		json.NewEncoder(w).Encode(proxyData)
		return
	}

	httpProxy := strings.TrimPrefix(parts[0], "http_proxy=")
	https := strings.TrimPrefix(parts[1], "https_proxy=")
	none := strings.TrimPrefix(parts[2], "no_proxy=")

	proxyData := _Proxy{HTTPProxy: httpProxy, HTTPSProxy: https, NoProxy: none}
	json.NewEncoder(w).Encode(proxyData)
}

func persistUpdateFile(source io.Reader, dest string) error {
	file, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, source)
	if err != nil {
		return err
	}
	return nil
}

//UpdateFile - struct to contain the json generated by edgeos-swupdate-status
type UpdateFile struct {
	ID              string `json:"ID"`
	UpdateStatus    string `json:"UpdateStatus"`
	PerviousVersion string `json:"PerviousOSVersion"`
	CurrentVersion  string `json:"CurrentOSVersion"`
	ErrorMessage    string `json:"ErrorMessage"`
}

//UpdateStatus - get the status of the last update
func (provider *DBus) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	statusFileLocation := provider.Conf.EdgeOS.UpdateStatusFile
	//check for file existence.
	if _, err := os.Stat(statusFileLocation); os.IsNotExist(err) {
		log.Errorf("file does not exist")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	//load the file contents into a struct, file will always contain a json.
	// json defined in /usr/bin/swupdate-status
	statusJSON := UpdateFile{}
	file, err := ioutil.ReadFile(statusFileLocation)
	if err != nil {
		log.Errorf("[A/B Update Status] stack-trace: %s", err.Error())
		response := basicDBusResponse{Status: "FAIL", Error: err.Error()}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}
	err = json.Unmarshal(file, &statusJSON)
	if err != nil {
		log.Errorf("[A/B Update Status] stack-trace: %s", err.Error())
		response := basicDBusResponse{Status: "FAIL", Error: err.Error()}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}
	json.NewEncoder(w).Encode(statusJSON)
	return
}

func (provider *DBus) cleanUpTarballs(path string) error {
	log.Infof("attempting to remove tarballs located in %s", path)
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	emsUID := uint32(os.Getuid())
	for _, file := range files {
		if file.Sys() != nil {
			fileUID := file.Sys().(*syscall.Stat_t).Uid
			if fileUID == emsUID {
				//eat the error, ignore if we cannot remove.
				_ = os.Remove(strings.Join([]string{path, file.Name()}, "/"))
			}
		}
	}
	return nil
}

//Update - Host update using swupdate.
func (provider *DBus) Update(w http.ResponseWriter, r *http.Request) {
	//TODO: regex to only accept files with certain extention?
	log.Info("[A/B Update] update detected!")
	extractDir := provider.Conf.DataVolume
	provider.cleanUpTarballs(extractDir)
	// Save incoming file to disk.
	err := r.ParseMultipartForm(0)
	if err != nil {
		log.Errorf("[A/B Update] stack-trace: %s", err.Error())
		response := basicDBusResponse{Status: "FAIL", Error: err.Error()}
		json.NewEncoder(w).Encode(response)
		return
	}
	// Get the update file that we need out.
	//file will be located in "/tmp/" + fileHeader.Filename
	file, fileHeader, err := r.FormFile("artifact")
	if err != nil {
		log.Errorf("[A/B Update] stack-trace: %s", err.Error())
		response := basicDBusResponse{Status: "FAIL", Error: err.Error()}
		json.NewEncoder(w).Encode(response)
		return
	}
	defer file.Close()

	updateFileDest := filepath.Join(extractDir, fileHeader.Filename)
	log.Debugf("Path to update file: ", updateFileDest)
	err = persistUpdateFile(file, updateFileDest)
	if err != nil {
		log.Errorf("Could not persist update data: \n\t%v", err)
		response := basicDBusResponse{Status: "FAIL", Error: err.Error()}
		json.NewEncoder(w).Encode(response)
		return
	}

	log.Debugf("set environment parameters: %s", updateFileDest)
	// tell the swupdate service where the swupdate file is located.
	bus := provider.Bus.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	hupParams := strings.Join([]string{"HUP_IMAGE=", updateFileDest}, "")
	call := bus.Call("org.freedesktop.systemd1.Manager.SetEnvironment", 0, []string{hupParams})
	if call.Err != nil {
		log.Errorf("Could not set environment: \n\t%v", call.Err)
		response := basicDBusResponse{Status: "FAIL", Error: call.Err.Error()}
		json.NewEncoder(w).Encode(response)
		return
	}

	call = bus.Call("org.freedesktop.systemd1.Manager.StartUnit", 0, "swupdate.service", "fail")
	if call.Err != nil {
		log.Errorf("Could not start update service: \n\t%v", call.Err)
		response := basicDBusResponse{Status: "FAIL", Error: call.Err.Error()}
		json.NewEncoder(w).Encode(response)
		return
	}

	//successs
	log.Infof("No errors detected, Update successful.")
	response := basicDBusResponse{Status: "OK", Error: ""}
	json.NewEncoder(w).Encode(response)
	return
}

//Version - Get version information mock
func (provider *DBus) Version(w http.ResponseWriter, r *http.Request) {
	var resp _VER
	cmd := exec.Command("sh", "-c", "cat /etc/lsb-release")

	// run the command and get its output as an array of bytes.
	out, err := cmd.CombinedOutput()
	if err != nil {
		resp := _VER{Status: "ERROR", Error: err.Error(), Version: ""}
		json.NewEncoder(w).Encode(resp)
		return
	}

	var found bool
	var version string
	found = false
	temp := strings.Split(string(out), "\n")
	for _, str := range temp {
		temp2 := strings.Split(str, "=")
		if len(temp) < 2 {
			// somehing weird happened
			break
		} else if temp2[0] == "DISTRIB_RELEASE" {
			found = true
			version = temp2[1]
			break
		}
		//else check next index
	}
	if !found {
		resp = _VER{Status: "ERROR", Error: "Could not find version information", Version: ""}
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp = _VER{Status: "OK", Error: "", Version: version}
	json.NewEncoder(w).Encode(resp)
	return

}

// SetDockerProxy - docker proxy settings
func (provider *DBus) SetDockerProxy(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	var t _Proxy
	err := decoder.Decode(&t)
	if err != nil {
		log.Errorf("Could not parse request body:\n%v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500 - Internal Server Error"))
		return
	}

	dockerProxyConfigLocation := provider.Conf.DockerProxyConfig

	fileString := "[Service]\nEnvironment=\"HTTP_PROXY=%s\"\nEnvironment=\"HTTPS_PROXY=%s\"\nEnvironment=\"NO_PROXY=%s\"\n"
	fileString = fmt.Sprintf(fileString, t.HTTPProxy, t.HTTPSProxy, t.NoProxy)
	err = ioutil.WriteFile(dockerProxyConfigLocation, []byte(fileString), 0644)
	output, err := exec.Command("systemctl", "daemon-reload").Output()
	if err != nil {
		log.Errorf("Could not execute daemon reload:\n%v", err)
		//return status code 500 Internal Server Error
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500 - Internal Server Error"))
		return
	}
	log.Infof("daemone reload output: %s", string(output))
	output, err = exec.Command("systemctl", "restart", "docker").Output()
	if err != nil {
		log.Errorf("Could not restart Docker:\n%v", err)
		//return 500 Internal Server Error
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500 - Internal Server Error"))
		return
	}
	log.Infof("restart docker output: %s", string(output))

	//form a response, should be somethign like {"status": "OK", "error":""}
	b, err := json.Marshal(t)
	json.NewEncoder(w).Encode(string(b))
}

// GetDockerProxy - docker proxy settings
func (provider *DBus) GetDockerProxy(w http.ResponseWriter, r *http.Request) {
	var t _Proxy
	var httpProxy = ""
	var httpsProxy = ""
	var noProxy = ""
	dockerProxyConfigLocation := "/mnt/conf/root-overlay/etc/systemd/system/docker.service.d/http-proxy.conf"
	dockerProxyConfig, err := os.Open(dockerProxyConfigLocation)
	if err != nil {
		log.Errorf("Could not find the docker proxy configuration file:\n%v", err)
		//return 500 Internal Server Error
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500 - Internal Server Error"))
		return
	}
	defer dockerProxyConfig.Close()

	scanner := bufio.NewScanner(dockerProxyConfig)
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		//process line
		//line will be one of three cases:
		//1) [Service]
		//2) Environment="HTTP(S)(NO)_PROXY="
		//3) Environment="HTTP(S)(NO)_PROXY=(...)"

		if strings.Contains(line, "\"") {
			line = strings.Replace(line, "\"", "", -1)
			if strings.Contains(line, "Environment=") {
				line = strings.Replace(line, "Environment=", "", -1)
				eqSplit := strings.Split(line, "=")
				if len(eqSplit) < 2 {
					//HTTP_PROXY is not set in the conf file
					continue
				} else {
					//lines should now only be:
					//HTTP(S)(NO)_PROXY=(...)
					if strings.Contains(line, "HTTP_PROXY") {
						httpProxy = eqSplit[1]
					} else if strings.Contains(line, "HTTPS_PROXY") {
						httpsProxy = eqSplit[1]
					} else if strings.Contains(line, "NO_PROXY") {
						noProxy = eqSplit[1]
					}
				}
			}
		}
	}

	t = _Proxy{HTTPProxy: httpProxy,
		HTTPSProxy: httpsProxy,
		NoProxy:    noProxy}

	json.NewEncoder(w).Encode(t)
}

//GetHosts - Returns a list of user managed host/IP address pairs
func (provider *DBus) GetHosts(w http.ResponseWriter, r *http.Request) {
	//Ensure host file exists
	f, err := os.OpenFile(provider.Conf.HostsFilePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		log.Errorf("Error when attempting to open Hosts File:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	f.Close()
	//Retrieve Hosts from DBus
	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.HostsGet", dbus.FlagNoAutoStart, provider.Conf.HostsFilePath)
	if nil != call.Err {
		log.Errorf("Error when attempting to call HostsGet dbus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	var hostsJSON string
	call.Store(&hostsJSON)
	var hostsDBus []_HostDBus
	err = json.Unmarshal([]byte(hostsJSON), &hostsDBus)
	if nil != err {
		log.Errorf("Could not parse DBus response:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	//Convert into EMS responses. Note that the DBus service is sophisticated
	//enough to understanding mapping multiple hostnames to the same IP Address
	//but EMS intentionally assumes there is only ever one hostname mapped
	//to a given IP Address.
	response := make([]_Host, len(hostsDBus))
	for i, hostDBus := range hostsDBus {
		hostEntry := _Host{hostDBus.IP, ""}
		if len(hostDBus.Hosts) > 0 {
			hostEntry.Name = hostDBus.Hosts[0]
		}
		response[i] = hostEntry
	}
	json.NewEncoder(w).Encode(response)
	return
}

//SetHosts - Sets the custom hosts file to contain the user supplied list of IP/Host mappings
func (provider *DBus) SetHosts(w http.ResponseWriter, r *http.Request) {
	//Ensure host file exists; if it exists truncate.
	//This ensures the custom hosts file matches the supplied values exactly
	f, err := os.OpenFile(provider.Conf.HostsFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Errorf("Error when attempting to open Hosts File:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	f.Close()
	decoder := json.NewDecoder(r.Body)
	var newHosts []_Host
	err = decoder.Decode(&newHosts)
	if err != nil {
		log.Errorf("Could not parse request body:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	newHostsDBus := make([]_HostDBus, len(newHosts))
	for i, newHost := range newHosts {
		newHostDBus := _HostDBus{newHost.IP, make([]string, 1)}
		newHostDBus.Hosts[0] = newHost.Name
		newHostsDBus[i] = newHostDBus
	}
	b, errMarsh := json.Marshal(newHostsDBus)
	if nil != errMarsh {
		log.Errorf("Could not marshal requested hosts:\n%v", errMarsh)
		handle(errMarsh.Error(), http.StatusInternalServerError, w)
		return
	}
	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.HostsSet", dbus.FlagNoAutoStart, provider.Conf.HostsFilePath, string(b))
	if nil != call.Err {
		log.Errorf("Error when attempting to call HostsSet dbus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	var hostsJSON string
	call.Store(&hostsJSON)
	//Convert to objects
	var hostsDBus []_HostDBus
	err = json.Unmarshal([]byte(hostsJSON), &hostsDBus)
	if nil != err {
		log.Errorf("Could not parse DBus response:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	//Convert into EMS responses. Note that the DBus service is sophisticated
	//enough to understanding mapping multiple hostnames to the same IP Address
	//but EMS intentionally assumes there is only ever one hostname mapped
	//to a given IP Address.
	response := make([]_Host, len(hostsDBus))
	for i, hostDBus := range hostsDBus {
		hostEntry := _Host{hostDBus.IP, ""}
		if len(hostDBus.Hosts) > 0 {
			hostEntry.Name = hostDBus.Hosts[0]
		}
		response[i] = hostEntry
	}
	json.NewEncoder(w).Encode(response)
	return
}

func getContainerIP(containerName string) string {
	output, err := exec.Command("sh", "-c", fmt.Sprintf("docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s", containerName)).Output()
	if err != nil {
		return ""
	}
	ipAddrs := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(ipAddrs) > 1 {
		return ""
	}
	return ipAddrs[0]
}

//StartWhitelist - Adds an IP address whitelisting chain to iptables.
func (provider *DBus) StartWhitelist(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t _Whitelist
	err := decoder.Decode(&t)
	if err != nil {
		log.Errorf("Could not parse request body:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	if "" == t.ContainerName || 0 == len(t.WhitelistIPs) {
		handle("Invalid Request", http.StatusBadRequest, w)
		return
	}
	containerIP := getContainerIP(t.ContainerName)
	if "" == containerIP || 0 == len(containerIP) {
		handle("Invalid Request", http.StatusBadRequest, w)
		return
	}
	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.WhitelistStart", dbus.FlagNoAutoStart, containerIP, t.WhitelistIPs)
	if nil != call.Err {
		log.Errorf("Error when attempting to call Whitelist DBus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	resp := basicDBusResponse{Status: "OK", Error: ""}
	json.NewEncoder(w).Encode(resp)
	return
}

//StopWhitelist - Removes an IP address whitelisting chain from iptables.
func (provider *DBus) StopWhitelist(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t _Whitelist
	err := decoder.Decode(&t)
	if err != nil {
		log.Errorf("Could not parse request body:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	if "" == t.ContainerName || 0 == len(t.WhitelistIPs) {
		handle("Invalid Request", http.StatusBadRequest, w)
		return
	}
	containerIP := getContainerIP(t.ContainerName)
	if "" == containerIP {
		handle("Invalid Request - no container with that name", http.StatusBadRequest, w)
		return
	}
	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.WhitelistStop", dbus.FlagNoAutoStart, containerIP, t.WhitelistIPs)
	if nil != call.Err {
		log.Errorf("Error when attempting to call Whitelist DBus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	resp := basicDBusResponse{Status: "OK", Error: ""}
	json.NewEncoder(w).Encode(resp)
	return
}

//StatusSSH - Retreive SSH server status from the local machine.
func (provider *DBus) StatusSSH(w http.ResponseWriter, r *http.Request) {
	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.StatusSSH", dbus.FlagNoAutoStart, provider.Conf.SSHServiceName)
	if nil != call.Err {
		log.Errorf("Error when attempting to call EnableSSH DBus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	var status string
	call.Store(&status)
	resp := basicDBusResponse{Status: status, Error: ""}
	json.NewEncoder(w).Encode(resp)
	return
}

//EnableSSH - Enables SSH access on the local machine.
func (provider *DBus) EnableSSH(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t _SSH
	err := decoder.Decode(&t)
	if err != nil {
		log.Errorf("Could not parse request body:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	if "" == t.IPAddress || "" == t.SSHPubKey {
		handle("Invalid Request", http.StatusBadRequest, w)
		return
	}

	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.EnableSSH", dbus.FlagNoAutoStart, provider.Conf.SSHServiceName, t.IPAddress, provider.Conf.SSHPort, provider.Conf.SSHAuthKeysFile, provider.Conf.SSHUid, provider.Conf.SSHGid, t.SSHPubKey)
	if nil != call.Err {
		log.Errorf("Error when attempting to call EnableSSH DBus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	resp := basicDBusResponse{Status: "OK", Error: ""}
	json.NewEncoder(w).Encode(resp)
	return
}

//DisableSSH - Disables SSH access on the local machine.
func (provider *DBus) DisableSSH(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t _SSH
	err := decoder.Decode(&t)
	if err != nil {
		log.Errorf("Could not parse request body:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	if "" == t.IPAddress {
		handle("Invalid Request", http.StatusBadRequest, w)
		return
	}

	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.DisableSSH", dbus.FlagNoAutoStart, provider.Conf.SSHServiceName, t.IPAddress, provider.Conf.SSHPort, provider.Conf.SSHAuthKeysFile, provider.Conf.SSHUid, provider.Conf.SSHGid)
	if nil != call.Err {
		log.Errorf("Error when attempting to call DisableSSH DBus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	resp := basicDBusResponse{Status: "OK", Error: ""}
	json.NewEncoder(w).Encode(resp)
	return
}

//CPUMetrics - Retrieves CPU metrics from the local machine.
func (provider *DBus) CPUMetrics(w http.ResponseWriter, r *http.Request) {
	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.CPUStats", dbus.FlagNoAutoStart)
	if nil != call.Err {
		log.Errorf("Error when attempting to call CPUStats DBus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	metricsStr := string("")
	call.Store(&metricsStr)
	metrics := _CPUStats{}
	err := json.Unmarshal([]byte(metricsStr), &metrics)
	if nil != err {
		log.Errorf("Could not parse DBus response:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	json.NewEncoder(w).Encode(metrics)
	return
}

//DiskMetrics - Retrieves Disk metrics from the local machine.
func (provider *DBus) DiskMetrics(w http.ResponseWriter, r *http.Request) {
	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.DiskStats", dbus.FlagNoAutoStart)
	if nil != call.Err {
		log.Errorf("Error when attempting to call DiskStats DBus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	metricsStr := string("")
	call.Store(&metricsStr)
	metrics := _DiskStats{}
	err := json.Unmarshal([]byte(metricsStr), &metrics)
	if nil != err {
		log.Errorf("Could not parse DBus response:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	json.NewEncoder(w).Encode(metrics)
	return
}

//NetMetrics - Retrieves Network metrics from the local machine.
func (provider *DBus) NetMetrics(w http.ResponseWriter, r *http.Request) {
	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.NetStats", dbus.FlagNoAutoStart)
	if nil != call.Err {
		log.Errorf("Error when attempting to call NetStats DBus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	metricsStr := string("")
	call.Store(&metricsStr)
	metrics := _NetStats{}
	err := json.Unmarshal([]byte(metricsStr), &metrics)
	if nil != err {
		log.Errorf("Could not parse DBus response:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	json.NewEncoder(w).Encode(metrics)
	return
}

//MemMetrics - Retrieves memory metrics from the local machine.
func (provider *DBus) MemMetrics(w http.ResponseWriter, r *http.Request) {
	bus := provider.Bus.Object("com.ge.edgeos", "/com/ge/edgeos")
	call := bus.Call("com.ge.edgeos.MemStats", dbus.FlagNoAutoStart)
	if nil != call.Err {
		log.Errorf("Error when attempting to call MemStats DBus service:\n%v", call.Err)
		handle(call.Err.Error(), http.StatusInternalServerError, w)
		return
	}
	metricsStr := string("")
	call.Store(&metricsStr)
	metrics := _MemStats{}
	err := json.Unmarshal([]byte(metricsStr), &metrics)
	if nil != err {
		log.Errorf("Could not parse DBus response:\n%v", err)
		handle(err.Error(), http.StatusInternalServerError, w)
		return
	}
	json.NewEncoder(w).Encode(metrics)
	return
}
