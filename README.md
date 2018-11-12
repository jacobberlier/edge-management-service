# Management Service

This service will expose a REST interface for accessing various other services and functions on EdgeOS.

## Building

Run `make` or `make build` to compile your app.  This will use a Docker image
to build your app, with the current directory volume-mounted into place.  This
will store incremental state for the fastest possible build.  Run `make
all-build` to build for all architectures.

Run `make image` to build the image  It will calculate the image
tag based on the most recent git tag, and whether the repo is "dirty" since
that tag (see `make version`).  Run `make all-image` to build images
for all architectures.

Run `make test` to test the image.  Format checks, lint, and unit tests will be
executed.

Run `make push` to push the container image to `REGISTRY`.  Run `make all-push`
to push the container images for all architectures.

Run `make clean` to clean up.

### Dependency Management

This template uses golang's `dep` tool to manage/vendor dependencies. The documentation for that tool can be found here: https://github.com/golang/dep

The `dep` tools is downloaded when the builder image is created, so you should execute that command in the builder container using the `make build-shell` target. We used `dep init` to initialize the `vendor` folder and Gopkg files. Use `dep ensure` when dependencies are added or removed.

#### Adding Dependencies

add your dependency link to the `<prject-dir>/hack/tool-deps.sh`


If for example you wanted to add the "example" package hosted on gihub.com/example/example
The process you would follow would be:

`cd <project-dir>`
`vim hack/tool-deps.sh`

Now add a `\` to the end of the line of the last dependency, and add your github link on the next line.
~~~
#!/bin/bash
...

go get
    github.com/tools/godep \
    ...
    github.com/gorilla/mux \
    github.com/example/example </span>
~~~
Now all you will need to do is re-run make.
The Makefile will handle installing the dependency.

Removing dependencies is the reverse of this operation.
We recommend that when you want to remove dependencies, run `make clean` before attempting to build again.

### Endpoints

There are two main functions of the EMS, The first of which is device management.
This means we can configure our devices remotely.
The second use case is container management. EMS proxies container management requests through to cappsd.
Cappsd is the container-apps-service running on EdgeOS.

Since the EMS is a Rest service, it is useful to have a list of endpoints and their functions.
All endpoints in this list are defined in the `handlers/handler.go` file.
Listing them here with a brief summary of what they do, is good to have as well.

Where specific choices can be made for endpoints, I will attempt to make that clear by separating choices like this:
`(choice 1 | choice 2 | choice 3 |... | choice n)`
Nested choices will follow the following format
`(choice1:(sub1 | sub2 | ... | subN) | choice2:(sub1 | sub2 | ... | subN) | ... | choiceN:(sub1 | sub2 | ... | subN))`


#### Cappsd
  These endpoints are for proxying requests through to cappsd.

`/applications` - GET - list all running docker containers on device, that cappsd is aware of.
`/applications/ping` - GET - ping endpoint, always returns {"status":"ok", "error":""}
`/application/deploy` - POST - deploy container via cappsd
`/application/details/{id}` - GET - gets more detailed information about a running container
`/application/status/{id}` - GET - returns a less detailed status report for a running container
`/application/restart/{id}` - POST - restarts a running container, effectively the same as stopping then starting the same container.
`/application/start/{id}` - POST - starts a stopped container
`/application/stop/{id}` - POST - stops a running container
`/application/purge/{id}` - POST - removes/purges container from docker/cappsd


`/api/v1/containers` - GET - Edge Agent parity, endpoint proxies to `/applications`
`/api/v1/containers/ping` - GET - Edge Agent parity(does not exist in EA anymore), proxies to `/applications/ping`
`/api/v1/container/instances` - POST - Edge Agent parity, proxies to `/applications/deploy`
`/api/v1/container/instances/{instanceId}/{(restart | start | stop | purge)}` - POST - Edge Agent parity, proxies to `/application/(restart|start|stop|purge)`

#### Device Management
  These endpoints are available for remote device management and configuration

##### Network Management

Rest interface for configuration for network interfaces.

`/api/v1/host/network/interfaces` - GET - list network interfaces available for configuration
`/api/v1/host/network/interfaces/{interface}` - GET - More detailed information about supplied interface
`/api/v1/host/network/interfaces/{interface}/{(manual | dhcp)}` - PUT - update interface with supplied information in body of request.
`/api/v1/host/network/ntp` - GET - Get current NTP configuration
`/api/v1/host/network/ntp` - POST - Set NTP configuration, then restart systemd-timesyncd
`/api/v1/host/network/proxy` - GET - Get the proxy information that Edge Agent is using
`/api/v1/host/network/proxy` - POST - Set proxy for Edge Agent.
`/api/v1/host/dockerproxy` - GET - gets the current docker proxy configuration
`/api/v1/host/dockerproxy` - POST - Sets the docker proxy, in http-proxy.conf, then restarts docker.

##### SWUpdate

Endpoints related to host update, AKA a/b update, AKA swupdate

`/api/v1/host/update` - POST - Accepts a multipart file upload, and attempts to run swupdate with the tarball supplied. This function will wait until a state of READY or FAILED to resolve
`/api/v1/host/state` - GET - Gets the state of the last run host update.

##### Logging

Rest endpoints for retrieving logs from device/docker containers

`/api/v1/host/logs/sources` - GET - List available log sources,
`/api/v1/host/logs/{(services | containers)}/{(services:(systemd | kernel) | containers:(containerId))}` - GET - Fetches logs using path parameters to determine what logs to get
`/api/v1/host/logs/{(services | containers)}/{(services:(systemd | kernel) | containers:(containerId))}` - DELETE - clears logs of the selected type


##### Edge Agent

Endpoints that EMS uses to communicate with Edge Agent

`/api/v1/host/enroll` - POST | PUT - proxies requests to Edge Agent to enroll device in Predix Cloud.

##### Misc

Endpoints that do not fit other categories.

`/api/v1/host/version` - GET - Returns version information for the device




