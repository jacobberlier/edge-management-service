#!/bin/sh

set -o errexit
set -o nounset
set -o pipefail

# This script tests golang source code.
#
# Requirements:
# - Expects the source folders to be tested as argument
# - The script is intended to be run inside the docker container specified
#   in the Dockerfile for the build container. In other words:
#   DO NOT CALL THIS SCRIPT DIRECTLY.
# - The right way to call this script is to invoke "make" from
#   your checkout of the repository.
#   the Makefile will do a "docker build ... " and then
#   "docker run hack/test.sh" in the resulting image.
#

TARGETS=$(for d in "$@"; do echo ./$d/...; done)

go test -v ${TARGETS}
echo