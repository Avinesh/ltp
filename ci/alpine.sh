#!/bin/sh -eux
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2019-2024 Petr Vorel <petr.vorel@gmail.com>

apk update

apk add \
	acl-dev \
	autoconf \
	automake \
	clang \
	curl \
	jq \
	gcc \
	git \
	acl-dev \
	keyutils-dev \
	libaio-dev \
	libcap-dev \
	libselinux-dev \
	libsepol-dev \
	libtirpc-dev \
	linux-headers \
	make \
	musl-dev \
	numactl-dev \
	openssl-dev \
	pkgconfig

cat /etc/os-release

echo "WARNING: remove unsupported tests (until they're fixed)"
cd $(dirname $0)/..
rm -rfv \
	testcases/kernel/syscalls/fmtmsg/fmtmsg01.c \
	testcases/kernel/syscalls/timer_create/timer_create01.c \
	testcases/kernel/syscalls/timer_create/timer_create03.c

cd -
