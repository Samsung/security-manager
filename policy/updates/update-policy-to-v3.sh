#!/bin/sh -e

export PATH=/sbin:/usr/sbin:/bin:/usr/bin

. /etc/tizen-platform.conf

systemctl stop security-manager.service security-manager.socket


label_mapping=`mktemp`

### Fetch application label mapping
sqlite3 >$label_mapping -noheader -separator ' ' $TZ_SYS_DB/.security-manager.db '
SELECT DISTINCT
       "User::App::" || app_name,
       "User::Pkg::" || pkg_name || CASE WHEN is_hybrid THEN "::App::" || app_name ELSE "" END
       FROM user_app_pkg_view'

echo "Migrating policy for `sort -u $label_mapping | wc -l` application labels"

### Migrate Cynara policy
generic_buckets="PRIVACY_MANAGER ADMIN MAIN MANIFESTS"
usertype_buckets=`ls $TZ_SYS_RO_SHARE/security-manager/policy/usertype-*profile |
    sed -r 's|.*/usertype-(.*).profile$|USER_TYPE_\1|' |
    tr '[:lower:]' '[:upper:]'`

policy_tmp=`mktemp`
for bucket in $generic_buckets $usertype_buckets
do
    [ "$bucket" = "PRIVACY_MANAGER" ] && bucket=""
    echo "Migrating Cynara bucket '$bucket'"

    cyad --list-policies=$bucket --all >$policy_tmp

    cat $label_mapping |
    while read app_label_old app_label_new
    do
        echo '-e s/\\b'$app_label_old'\\b/'$app_label_new'/'
    done |
    xargs sed -i $policy_tmp

    cyad --erase=$bucket --recursive=no --client='#' --user='#' --privilege='#'
    cyad --set-policy --bucket=$bucket --bulk=- <$policy_tmp
done
rm -f $policy_tmp

### Migrate security-manager Smack policy
echo "Migrating Smack policy"

cd $TZ_SYS_VAR/security-manager
smackload --clear <rules-merged/rules.merged

cat $label_mapping |
while read app_label_old app_label_new
do
    echo '-e s/\\b'$app_label_old'\\b/'$app_label_new'/'
done |
xargs sed -i rules/* `find -type f -name apps-labels`

cat rules/* | tee rules-merged/rules.merged | smackload

systemctl start security-manager.service security-manager.socket

echo "Migration successful"
rm -f $label_mapping
