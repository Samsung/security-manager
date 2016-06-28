#!/bin/sh -e

# @file
# @author Lukasz Kostyra (l.kostyra@samsung.com)
# @brief  Security-manager Database Updater script

source /etc/tizen-platform.conf

# Some useful constants
PATH=/bin:/usr/bin:/sbin:/usr/sbin
db="$TZ_SYS_DB/.security-manager.db"
db_journal="$db-journal"
sm_dir="/usr/share/security-manager/db"
db_updates="$sm_dir/updates"
db_update_file_prefix="update-db-to-v"
db_main="$sm_dir/db.sql"
sqlitecmd="sqlite3"

[ ! -f $db_main ] && echo "Main DB schema not found!" && exit 1
[ ! -e $db ] && echo "Database not found!" && exit 1

if [ `stat -c %s $db` -eq 0 ]
then
    echo "Database empty, creating from scratch."
    $sqlitecmd "$db" < "$db_main"
    exit
fi

[ ! -d $db_updates ] && echo "Update scripts are not found!" && exit 1

# Extract current db version and target version
db_version="`\"$sqlitecmd\" \"$db\" 'PRAGMA user_version;'`"
db_pragma_user="`grep 'PRAGMA user_version' $db_main`"
db_version_new="`echo \"$db_pragma_user\" | sed -r 's/.* ([0-9]+).*/\1/'`"

echo "Current version: $db_version; version to update: $db_version_new"

[ -z "$db_version_new" ] && echo "Unable to parse new DB version - missing PRAGMA user_version?" && exit 1
[ $db_version -eq $db_version_new ] && echo "Database is already up to date." && exit
[ $db_version -gt $db_version_new ] && echo "Downgrading is not possible with this tool." && exit 1

# Update loop - apply all updates in order
for i in `seq $((db_version+1)) $db_version_new`
do
    echo "Updating $db to v$i (target version is $db_version_new)"
    db_update="$db_updates/$db_update_file_prefix$i.sql"
    [ ! -e "$db_update" ] && echo "Missing update script $db_update" && exit 1
    $sqlitecmd "$db" < "$db_update"
done

# Finally, introduce our main db.sql to update views and others
echo "Applying new views and changes from main schema"
$sqlitecmd "$db" < "$db_main"
