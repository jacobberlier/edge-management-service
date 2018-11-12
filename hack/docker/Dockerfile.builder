FROM golang:1.11.2-alpine3.8

RUN set -ex \
	&& apk add --no-cache \
		bash \
		curl \
		git \
		gcc \
		libc-dev
