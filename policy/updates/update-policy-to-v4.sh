#!/bin/sh -e

export PATH=/sbin:/usr/sbin:/bin:/usr/bin

. /etc/tizen-platform.conf

systemctl stop security-manager.service security-manager.socket


app_label_nonhybrid=`mktemp`

### Fetch application label mapping
sqlite3 >$app_label_nonhybrid -noheader -separator ' ' $TZ_SYS_DB/.security-manager.db '
SELECT DISTINCT
       app_name,
       "User::Pkg::" || pkg_name
       FROM user_app_pkg_view
       WHERE is_hybrid=0'

echo "Migrating policy for `sort -u $app_label_nonhybrid | wc -l` applications"

### Migrate security-manager Smack policy
echo "Migrating Smack policy"

cd $TZ_SYS_VAR/security-manager

cat $app_label_nonhybrid |
while read app_name app_label
do
    echo "$app_label $app_label rwxat-" >> rules/app_$app_name
done

cat rules/* | tee rules-merged/rules.merged | smackload

systemctl start security-manager.service security-manager.socket

echo "Migration successful"
rm -f $app_label_nonhybrid
