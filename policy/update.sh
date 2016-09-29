#!/bin/sh -e

export PATH=/bin:/usr/bin:/sbin:/usr/sbin

. /etc/tizen-platform.conf

policy_version_file=$TZ_SYS_VAR/security-manager/policy-version
updates_dir=$TZ_SYS_RO_SHARE/security-manager/policy/updates

current_version=`cat $policy_version_file`
for file in `ls -v $updates_dir/update-policy-to-v*.sh`
do
    version=`echo $file | sed -r 's/.*-v([0-9]+)\.sh$/\1/'`
    if [ -z $current_version ]
    then
        ### No need to for an update
        echo $version >$policy_version_file
    else
        if [ $version -gt $current_version ]
        then
            echo Updating policy to v$version
            $file
            current_version=$version
            echo $current_version >$policy_version_file
        fi
    fi
done
