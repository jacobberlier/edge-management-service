package provider

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.build.ge.com/PredixEdgeOS/management-service/config"
	"github.com/gorilla/mux"
)

//Cappsd - struct to contain information related to preforming cappsd operations.
type Cappsd struct {
	cappsdPort string
	Conf       config.Config
	Lock       sync.RWMutex
	Client     *http.Client
}

type basicCappsdResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

//NewCappsd - Creates a new cappsd provider object to allow for routing to cappsd functions.
func NewCappsd(cfg config.Config) (*Cappsd, error) {
	provider := new(Cappsd)
	provider.Conf = cfg
	if cfg.CappsdConf.UseUnixSocket == true {
		tr := &http.Transport{Dial: provider.FakeDial}
		provider.Client = &http.Client{Transport: tr}
	} else {
		provider.Client = &http.Client{}
	}
	return provider, nil
}

//FakeDial - used to dial the unix socket instead of makeing a rest call.
func (cappsd *Cappsd) FakeDial(proto, addr string) (conn net.Conn, err error) {
	return net.Dial("unix", cappsd.Conf.CappsdConf.UnixSocketLocation)
}

func handle(err string, statusCode int, w http.ResponseWriter) {
	log.Errorf("Error: %s", err)
	resp := basicCappsdResponse{Status: "FAIL", Error: err}
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

//Proxy - forward apps requests to the contianer apps service
func (cappsd *Cappsd) Proxy(w http.ResponseWriter, r *http.Request) {
	var containerID string
	var command string
	var req *http.Request
	regex, err := regexp.Compile("^\\/applications?(\\/|$).*")
	if err != nil {
		handle("Internal Server Error", http.StatusInternalServerError, w)
		return
	}
	if regex.MatchString(r.URL.Path) {
		//Old api endpoint called
		log.Infof("Old request detected: Routing Path: %v", r.URL.Path)
		parts := strings.Split(r.URL.Path, "/")
		parts = removeEmptyStrings(parts)
		if len(parts) < 1 {
			handle("Invalid URL", http.StatusBadRequest, w)
			return
		}
		//expect the first element to be an empty string, so check the second one.
		switch parts[0] {
		case "applications":
			//either ping or list applications.
			if len(parts) < 2 {
				//list applications
				containerID = ""
				command = "list"
			} else {
				//ping request or other, treat as ping
				containerID = ""
				command = "ping"
			}
		case "application":
			//start, stop, restart, purge, details, and status are length 3
			// deploy will be length 2
			if len(parts) < 3 {
				containerID = ""
				command = "deploy"
			} else {
				containerID = parts[2]
				command = parts[1]
			}
		default:
			handle("Invalid URL", http.StatusBadRequest, w)
			return
		}
		req, err = formReq(containerID, command, r)
		if err != nil {
			handle("Could not proxy request", http.StatusBadRequest, w)
			return
		}
	} else {
		log.Infof("New request detected: Routing Path: %v", r.URL.Path)
		parts := strings.Split(r.URL.Path, "/")
		parts = removeEmptyStrings(parts)
		log.Info(parts)
		switch len(parts) {
		case 2:
			// createKey, hasKey, or getKey
			containerID = ""
			command = parts[1]
		case 3:
			// list
			containerID = ""
			command = "list"
		case 4:
			//deploy or ping
			containerID = ""
			command = parts[3]
		case 6:
			//command
			vars := mux.Vars(r)
			containerID = vars["instanceId"]
			command = vars["command"]
		default:
			//invlaid path length
			handle("invalid URL", http.StatusBadRequest, w)
			return
		}

		req, err = formReq(containerID, command, r)
		if err != nil {
			log.Errorf("could not form request")
			handle("Could not proxy request", http.StatusBadRequest, w)
			return
		}
	}

	req.Header = r.Header
	resp, err := cappsd.Client.Do(req)
	if err != nil {
		log.Errorf("Could not preform client.Do, error: %v", err)
		handle("Could not proxy request", http.StatusInternalServerError, w)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		handle("Could not read body of cappsd response", http.StatusInternalServerError, w)
		return
	}
	w.Write(body)
}

func formReq(containerID string, command string, request *http.Request) (*http.Request, error) {
	//baseURL := "http://unix"
	baseURL := "http://localhost:9000"
	var path = ""
	switch command {
	case "start", "stop", "restart", "purge", "status", "kill":
		path = strings.Join([]string{"/application/", command, "/", containerID}, "")
	case "details":
		// /application/{id}
		path = strings.Join([]string{"/application/", containerID}, "")
	case "list":
		// /applications
		path = "/applications"
	case "ping":
		// /ping
		path = "/ping"
	case "deploy", "instances":
		// /deploy
		path = "/application/deploy"
	case "createKey":
		path = "/provision/createKey"
	case "hasKey":
		path = "/provision/hasKey"
	case "getKey":
		path = "/provision/getKey"
	default:
		//unrecognized command, return error.
		return nil, errors.New("unrecognized command, Invalid url")
	}

	url := strings.Join([]string{baseURL, path}, "")
	return http.NewRequest(request.Method, url, request.Body)
}

func removeEmptyStrings(input []string) []string {
	var output []string
	for _, element := range input {
		if element != "" {
			output = append(output, element)
		}
	}
	return output
}
