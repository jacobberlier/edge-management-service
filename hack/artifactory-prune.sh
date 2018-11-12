#!/bin/bash

set -o nounset
set -o pipefail

ARCH="$1"

FILES=$(/home/jenkins/jfrog rt search XBKLI-SNAPSHOT/apps/EMS-snapshots/${ARCH} \
    | grep "path" | awk '{print $2}' | tr "\"" " ")

TODAY=$(date +%Y%m%d)
YESTERDAY=$(date  --date="1 day ago" +%Y%m%d)

OUTDATED=$(echo $FILES | tr " " "\n" | grep -v -e $TODAY -e $YESTERDAY)

echo "Deleting snapshots older than 2 days:"
echo $OUTDATED | tr " " "\n"

if ! [ -z "$OUTDATED" ]
then
    for f in $(echo $OUTDATED | tr " " "\n")
    do
         /home/jenkins/jfrog rt del --quiet=true "$f"
    done
fi
