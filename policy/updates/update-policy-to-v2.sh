#!/bin/sh -e

export PATH=/sbin:/usr/sbin:/bin:/usr/bin

. /etc/tizen-platform.conf

find $TZ_SYS_VAR/security-manager -name apps-names |
while read file_old
do
    file_new=`dirname $file_old`/apps-labels
    sed 's/^/User::App::/' $f <$file_old >$file_new
    rm -f $file_old
done
