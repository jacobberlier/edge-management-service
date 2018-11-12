package config

import (
	"encoding/json"
	"io/ioutil"
)

//Config - struct populated by specified config file at start of runtime
type Config struct {
	ListenAddress     string        `json:"listen_address"`
	DBusPort          string        `json:"dbus_port"`
	DataVolume        string        `json:"data_volume"`
	ReadTimeout       int           `json:"read_timeout"`
	WriteTimeout      int           `json:"write_timeout"`
	TLS               bool          `json:"useTLS"`
	Cert              string        `json:"cert_path"`
	Key               string        `json:"key_path"`
	NTPConf           string        `json:"ntp_config_location"`
	EnvFile           string        `json:"environment_file_location"`
	DockerProxyConfig string        `json:"docker_proxy_config_location"`
	AllowReboot       bool          `json:"allow_reboot"`
	CappsdConf        CappsdConf    `json:"container_management_conf"`
	NetworkConf       NetworkConf   `json:"network"`
	EdgeAgentConf     EdgeAgentConf `json:"edge_agent_conf"`
	EdgeOS            EdgeOSConfig  `json:"edgeOS"`
	RemoteManagement  bool          `json:"remote_management"`
	UnixSocketPath    string        `json:"unix_socket_path"`
	HostsFilePath     string        `json:"hosts_file_path"`
	SSHAuthKeysFile   string        `json:"ssh_auth_keys_file"`
	SSHUid            int           `json:"ssh_uid"`
	SSHGid            int           `json:"ssh_gid"`
	SSHPort           string        `json:"ssh_port"`
	SSHServiceName    string        `json:"ssh_service_name"`
}

//NetworkConf - network configuration object
type NetworkConf struct {
	SubnetDefault int `json:"default_subnet_mask"`
}

//CappsdConf - Cappsd communication configuration
type CappsdConf struct {
	UseUnixSocket      bool   `json:"use_unix_socket"`
	UnixSocketLocation string `json:"unix_socket_location"`
}

//EdgeAgentConf - EdgeAgent confgiuration values, for proxing enrollment requests
type EdgeAgentConf struct {
	UseUnixSocket      bool   `json:"use_unix_socket"`
	UnixSocketLocation string `json:"unix_socket_location"`
	EnrollmentEndpoint string `json:"enrollment_endpoint"`
	IP                 string `json:"ip"`
	Port               string `json:"port"`
	Protocol           string `json:"protocol"`
}

//EdgeOSConfig - edgeos configuration values
type EdgeOSConfig struct {
	UpdateStatusFile string `json:"update_file_location"`
}

//NewConfig - fetches config from specified location, returns fully populated Config struct
func NewConfig(path string) (Config, error) {
	cfg := Config{}
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	err = json.Unmarshal(file, &cfg)
	if err != nil {
		return cfg, err
	}

	return cfg, err
}
