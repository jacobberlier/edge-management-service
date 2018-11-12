#!/bin/sh

set -o errexit
set -o nounset
set -o pipefail

# This script builds the crawler executable and packages.
#
# Requirements:
# - Expects the following environment variables to be set:
#     -- VERSION e.g. 0.1.0
#     -- PKG     e.g. github.build.ge.com/insitu-robotics/crawlerd
#     -- ARCH    e.g. amd64
# - The script is intended to be run inside the docker container specified
#   in the Dockerfile for the build container. In other words:
#   DO NOT CALL THIS SCRIPT DIRECTLY.
# - The right way to call this script is to invoke "make" from
#   your checkout of the repository.
#   the Makefile will do a "docker build ... " and then
#   "docker run hack/build.sh" in the resulting image.
#

# Version prep
BUILDSTAMP=$(date -u '+%Y-%m-%d_%R:%S')
GITCOMMIT=$(git rev-parse --short HEAD)
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    GITCOMMIT="$GITCOMMIT-unsupported"
    echo "#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "# GITCOMMIT = $GITCOMMIT"
    echo "# The version you are building is listed as unsupported because"
    echo "# there are some files in the git repository that are in an uncommitted state."
    echo "# Commit these changes, or add to .gitignore to remove the -unsupported from the version."
    echo "# Here is the current list:"
    git status --porcelain --untracked-files=no
    echo "#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
fi

export CGO_ENABLED=0
export GOARCH="${ARCH}"

go install                                            \
    -installsuffix "static"                           \
    -ldflags "                                        \
        -X ${PKG}/version.Version=$VERSION            \
        -X ${PKG}/version.GitCommit=$GITCOMMIT        \
        -X ${PKG}/version.BuildStamp=$BUILDSTAMP      \
        -s -w"                                           \
    $(go list ./... | grep -v '/vendor')
