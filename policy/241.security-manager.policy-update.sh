#!/bin/sh -e

PATH=/bin:/usr/bin:/sbin:/usr/sbin

. /etc/tizen-platform.conf

exec "$TZ_SYS_RO_SHARE/security-manager/policy/update.sh"
