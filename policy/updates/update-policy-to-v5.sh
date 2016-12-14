#!/bin/sh -e

export PATH=/sbin:/usr/sbin:/bin:/usr/bin

. /etc/tizen-platform.conf

systemctl stop security-manager.service security-manager.socket
sed -r '/^\s*$/d' -i $TZ_SYS_VAR/security-manager/rules/* $TZ_SYS_VAR/security-manager/rules-merged/*
systemctl start security-manager.service security-manager.socket
