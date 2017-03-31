#!/bin/sh -e

export PATH=/sbin:/usr/sbin:/bin:/usr/bin

. /etc/tizen-platform.conf

systemctl restart cynara.service
systemctl stop security-manager.service security-manager.socket
cyad --list-policies="" --all --human-readable |
while IFS=';' read bucket client user privilege policy metadata
do
	[ "$policy" = "ask user" ] && cyad --set-policy --client="$client" --user="$user" --privilege="$privilege" --type="ASK_USER_LEGACY"
	[ "$policy" = "deny" ]     && cyad --set-policy --client="$client" --user="$user" --privilege="$privilege" --type="PRIVACY_DENY"
done

systemctl start security-manager.service security-manager.socket
