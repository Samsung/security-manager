#!/bin/sh -e

export PATH=/sbin:/usr/sbin:/bin:/usr/bin

. /etc/tizen-platform.conf

systemctl stop security-manager.service security-manager.socket

cyad --set-bucket=MANIFESTS_GLOBAL --type=DENY
cyad --set-bucket=MANIFESTS_LOCAL --type=DENY
cyad --set-policy --bucket=MAIN --client="*" --user="*" --privilege="*" --type=BUCKET \
     --metadata=MANIFESTS_GLOBAL

cyad --list-policies=MANIFESTS --user="*" --all |
sed 's/MANIFESTS/MANIFESTS_GLOBAL/g' |
cyad --set-policy --bucket=MANIFESTS_GLOBAL --bulk=-
cyad --erase=MANIFESTS --recursive=no --client="#" --user="*" --privilege="#"

cyad --list-policies=MANIFESTS --all |
grep -v "User::Pkg::" |
sed 's/MANIFESTS/MANIFESTS_GLOBAL/g' |
cyad --set-policy --bucket=MANIFESTS_GLOBAL --bulk=-

cyad --list-policies=MANIFESTS --all |
grep "User::Pkg::" |
sed 's/MANIFESTS/MANIFESTS_LOCAL/g' |
cyad --set-policy --bucket=MANIFESTS_LOCAL --bulk=-

cyad --list-policies=MANIFESTS_LOCAL --all |
while IFS=";" read bucket client user privilege policy
do
    cyad --set-policy --bucket=MANIFESTS_GLOBAL --client="$client" --user="$user" --privilege="*" \
         --type=BUCKET --metadata=MANIFESTS_LOCAL
done

cyad --delete-bucket=MANIFESTS

systemctl start security-manager.service security-manager.socket
