#!/bin/sh

# This script imports the golang language tooling.
#
# Requirements:
# - The script is intended to be run inside the docker container specified
#   in the Dockerfile for the build container. In other words:
#   DO NOT CALL THIS SCRIPT DIRECTLY.
# - The right way to call this script is to invoke "make" from
#   your checkout of the repository.
#   the Makefile will do a "docker build ... " and then
#   "docker run hack/tool-deps.sh" in the resulting image.
#

go get \
	github.com/tools/godep \
	github.com/golang/lint/golint \
	github.com/golang/dep/cmd/dep \
    github.com/gorilla/mux \
    github.com/godbus/dbus
