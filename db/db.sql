PRAGMA journal_mode = PERSIST;
PRAGMA foreign_keys = ON;
PRAGMA auto_vacuum = NONE;

BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 11;

CREATE TABLE IF NOT EXISTS pkg (
pkg_id INTEGER PRIMARY KEY,
name VARCHAR NOT NULL,
author_id INTEGER,
shared_ro INTEGER NOT NULL DEFAULT 0,
is_hybrid INTEGER NOT NULL DEFAULT 0,
UNIQUE (name)
FOREIGN KEY (author_id) REFERENCES author (author_id)
);

/* Application */
CREATE TABLE IF NOT EXISTS app (
app_id INTEGER PRIMARY KEY,
pkg_id INTEGER NOT NULL,
name VARCHAR NOT NULL,
version VARCHAR NOT NULL,
UNIQUE (name),
FOREIGN KEY (pkg_id) REFERENCES pkg (pkg_id)
);

/* Instance of 'app' installed for given user ('uid') */
CREATE TABLE IF NOT EXISTS user_app (
app_id INTEGER NOT NULL,
uid INTEGER NOT NULL,
PRIMARY KEY (app_id, uid),
FOREIGN KEY (app_id) REFERENCES app (app_id)
);

CREATE TABLE IF NOT EXISTS shared_path (
path_id INTEGER PRIMARY KEY,
path VARCHAR NOT NULL,
path_label VARCHAR NOT NULL,
owner_app_name TEXT NOT NULL,
UNIQUE (path)
);

CREATE TABLE IF NOT EXISTS app_private_sharing (
target_app_name TEXT NOT NULL,
path_id INTEGER NOT NULL,
counter INTEGER NOT NULL,
PRIMARY KEY (target_app_name, path_id)
FOREIGN KEY (path_id) REFERENCES shared_path (path_id)
);

CREATE TABLE IF NOT EXISTS privilege_group (
privilege_name VARCHAR NOT NULL,
group_name VARCHAR NOT NULL,
PRIMARY KEY (privilege_name, group_name)
);

CREATE TABLE IF NOT EXISTS author (
	author_id INTEGER PRIMARY KEY,
	name VARCHAR NOT NULL,
	UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS app_defined_privilege (
app_id INTEGER NOT NULL,
uid INTEGER NOT NULL,
privilege VARCHAR NOT NULL,
type INTEGER NOT NULL CHECK (type >= 0 AND type <= 1),
license VARCHAR,
FOREIGN KEY (app_id, uid) REFERENCES user_app (app_id, uid) ON UPDATE CASCADE ON DELETE CASCADE
);

-- This table contains privilege name that is also stored in
-- app_defined_privilege table.
-- It's time to consider using INTEGER instead VARCHAR and store
-- all names of privilege in new table (We will skip this in POC).
CREATE TABLE IF NOT EXISTS client_license (
app_id INTEGER NOT NULL,
uid INTEGER NOT NULL,
privilege VARCHAR NOT NULL,
license VARCHAR NOT NULL,
FOREIGN KEY(app_id, uid) REFERENCES user_app (app_id, uid) ON UPDATE CASCADE ON DELETE CASCADE
);

DROP VIEW IF EXISTS user_app_pkg_view;
CREATE VIEW user_app_pkg_view AS
SELECT
    user_app.uid,
    user_app.app_id,
    app.name as app_name,
    app.pkg_id,
    app.version as version,
    pkg.author_id,
    pkg.name as pkg_name,
    author.name as author_name,
    pkg.is_hybrid
FROM user_app
LEFT JOIN app USING (app_id)
LEFT JOIN pkg USING (pkg_id)
LEFT JOIN author USING (author_id);

DROP TRIGGER IF EXISTS user_app_pkg_view_insert_trigger;
CREATE TRIGGER user_app_pkg_view_insert_trigger
INSTEAD OF INSERT ON user_app_pkg_view
BEGIN
    SELECT RAISE(ABORT, 'Application already installed with different pkg_name')
        WHERE EXISTS (SELECT 1 FROM user_app_pkg_view
                      WHERE app_name=NEW.app_name
                      AND pkg_name!=NEW.pkg_name);

    SELECT RAISE(ABORT, 'Another application from this package is already installed with different author')
        WHERE EXISTS (SELECT 1 FROM user_app_pkg_view
                      WHERE pkg_name=NEW.pkg_name
                      AND author_name IS NOT NULL
                      AND NEW.author_name IS NOT NULL
                      AND author_name!=NEW.author_name);

    SELECT RAISE(ABORT, 'Hybrid flag set differently for existing package')
        WHERE EXISTS (SELECT 1 FROM user_app_pkg_view
                      WHERE is_hybrid!=NEW.is_hybrid
                      AND pkg_name=NEW.pkg_name);

    INSERT OR IGNORE INTO author(name) VALUES (NEW.author_name);
    INSERT OR IGNORE INTO pkg(name, author_id, is_hybrid) VALUES (
        NEW.pkg_name,
        (SELECT author_id FROM author WHERE name=NEW.author_name),
        NEW.is_hybrid);

    -- If pkg have already existed with empty author do update it
    UPDATE pkg SET author_id=(SELECT author_id FROM author WHERE name=NEW.author_name)
        WHERE name=NEW.pkg_name AND author_id IS NULL;

    -- If pkg have already existed with different version do update it
    UPDATE app SET version=NEW.version WHERE app_id=NEW.app_id;

    INSERT OR IGNORE INTO app (pkg_id, name, version) VALUES (
        (SELECT pkg_id FROM pkg WHERE name=NEW.pkg_name),
        NEW.app_name,
        NEW.version);

    INSERT OR IGNORE INTO user_app (app_id, uid) VALUES (
        (SELECT app_id FROM app WHERE name=NEW.app_name),
        NEW.uid);
END;

DROP TRIGGER IF EXISTS user_app_pkg_view_delete_trigger;
CREATE TRIGGER user_app_pkg_view_delete_trigger
INSTEAD OF DELETE ON user_app_pkg_view
BEGIN
    DELETE FROM user_app WHERE app_id=OLD.app_id AND uid=OLD.uid;
    DELETE FROM app WHERE app_id NOT IN (SELECT DISTINCT app_id FROM user_app);
    DELETE FROM pkg WHERE pkg_id NOT IN (SELECT DISTINCT pkg_id from app);
    DELETE FROM author WHERE author_id NOT IN (SELECT DISTINCT author_id FROM pkg WHERE author_id IS NOT NULL);
END;

DROP VIEW IF EXISTS app_private_sharing_view;
CREATE VIEW app_private_sharing_view AS
SELECT
    owner_app_name,
    target_app_name,
    path,
    path_label,
    counter
FROM app_private_sharing
LEFT JOIN shared_path USING (path_id);

DROP TRIGGER IF EXISTS app_private_sharing_view_insert_trigger;
CREATE TRIGGER app_private_sharing_view_insert_trigger
INSTEAD OF INSERT ON app_private_sharing_view
BEGIN
    SELECT RAISE(ABORT, 'Redefining owner_app_name for shared path is not allowed')
    WHERE EXISTS (SELECT path_id
                  FROM shared_path
                  WHERE path = NEW.path
                  AND owner_app_name <> NEW.owner_app_name);
    SELECT RAISE(ABORT, 'Redefining path_label for shared path is not allowed')
    WHERE EXISTS (SELECT path_id
                  FROM shared_path
                  WHERE path = NEW.path
                  AND path_label <> NEW.path_label);
    INSERT OR IGNORE INTO shared_path(path, path_label, owner_app_name) VALUES (
            NEW.path, NEW.path_label, NEW.owner_app_name);
    INSERT OR REPLACE INTO app_private_sharing VALUES (
            NEW.target_app_name,
            (SELECT path_id FROM shared_path WHERE NEW.path = path),
            COALESCE((SELECT counter FROM app_private_sharing
                      WHERE target_app_name = NEW.target_app_name
                      AND path_id = (SELECT path_id FROM shared_path WHERE NEW.path = path)),
                     0) + 1);
END;

DROP TRIGGER IF EXISTS app_private_sharing_view_update_trigger;
CREATE TRIGGER app_private_sharing_view_update_trigger
INSTEAD OF UPDATE OF counter ON app_private_sharing_view
BEGIN
    UPDATE app_private_sharing
    SET counter = NEW.counter
    WHERE   target_app_name = OLD.target_app_name
    AND     path_id = (SELECT path_id FROM shared_path WHERE path = OLD.path);
END;

DROP TRIGGER IF EXISTS app_private_sharing_view_remove_delete_trigger;
CREATE TRIGGER app_private_sharing_view_remove_delete_trigger
INSTEAD OF DELETE ON app_private_sharing_view
WHEN OLD.counter = 1
BEGIN
    DELETE FROM app_private_sharing
    WHERE path_id = (SELECT path_id FROM shared_path WHERE path = OLD.path)
    AND app_private_sharing.target_app_name = OLD.target_app_name;
    DELETE FROM shared_path WHERE path_id NOT IN (SELECT path_id FROM app_private_sharing) AND path = OLD.path;
END;

DROP TRIGGER IF EXISTS app_private_sharing_view_decrement_delete_trigger;
CREATE TRIGGER app_private_sharing_view_decrement_delete_trigger
INSTEAD OF DELETE ON app_private_sharing_view
WHEN OLD.counter > 1
BEGIN
    UPDATE app_private_sharing SET counter = OLD.counter - 1
    WHERE path_id = (SELECT path_id FROM shared_path WHERE path = OLD.path)
    AND app_private_sharing.target_app_name = OLD.target_app_name;
END;

DROP VIEW IF EXISTS app_defined_privilege_view;
CREATE VIEW app_defined_privilege_view AS
SELECT
    app.name AS app_name,
    pkg.name AS pkg_name,
    uid,
    privilege,
    type,
    license
FROM app_defined_privilege, app, pkg
WHERE app.app_id = app_defined_privilege.app_id
AND app.pkg_id = pkg.pkg_id;

DROP TRIGGER IF EXISTS app_defined_privilege_view_insert_trigger;
CREATE TRIGGER app_defined_privilege_view_insert_trigger
INSTEAD OF INSERT ON app_defined_privilege_view
BEGIN
    SELECT RAISE(ABORT, 'App defined privilege already defined by different application')
    WHERE EXISTS (SELECT 1 FROM app_defined_privilege_view
                  WHERE privilege=NEW.privilege AND app_name!=NEW.app_name);

    SELECT RAISE(ABORT, 'Application was not found')
    WHERE NOT EXISTS (SELECT 1 FROM user_app_pkg_view
                      WHERE uid=NEW.uid AND app_name=NEW.app_name);

    SELECT RAISE(ABORT, 'App defined privilege already defined')
    WHERE EXISTS (SELECT 1 FROM app_defined_privilege_view
                  WHERE uid=NEW.uid AND app_name=NEW.app_name AND privilege=NEW.privilege);

    INSERT OR IGNORE INTO app_defined_privilege (app_id, uid, privilege, type, license)
    VALUES ((SELECT app_id FROM app WHERE name=NEW.app_name), NEW.uid, NEW.privilege, NEW.type, NEW.license);
END;

DROP TRIGGER IF EXISTS app_defined_privilege_view_delete_trigger;
CREATE TRIGGER app_defined_privilege_view_delete_trigger
INSTEAD OF DELETE ON app_defined_privilege_view
BEGIN
    DELETE FROM app_defined_privilege
    WHERE app_id=(SELECT app_id FROM app WHERE name=OLD.app_name) AND uid=OLD.uid;
END;

DROP VIEW IF EXISTS client_license_view;
CREATE VIEW client_license_view AS
SELECT
    app.name AS app_name,
    pkg.name AS pkg_name,
    uid,
    privilege,
    license
FROM client_license, app, pkg
WHERE client_license.app_id = app.app_id
AND app.pkg_id = pkg.pkg_id;

DROP TRIGGER IF EXISTS client_license_view_insert_trigger;
CREATE TRIGGER client_license_view_insert_trigger
INSTEAD OF INSERT ON client_license_view
BEGIN
    SELECT RAISE(ABORT, 'Application was not found')
    WHERE NOT EXISTS (SELECT 1 FROM user_app_pkg_view
                      WHERE uid=NEW.uid AND app_name=NEW.app_name);

    SELECT RAISE(ABORT, 'Client privilege license already defined')
    WHERE EXISTS (SELECT 1 FROM client_license_view
                  WHERE uid=NEW.uid AND app_name=NEW.app_name AND privilege=NEW.privilege);

    INSERT OR IGNORE INTO client_license (app_id, uid, privilege, license)
    VALUES ((SELECT app_id FROM app WHERE name=NEW.app_name), NEW.uid, NEW.privilege, NEW.license);
END;

DROP TRIGGER IF EXISTS client_license_view_delete_trigger;
CREATE TRIGGER client_license_view_delete_trigger
INSTEAD OF DELETE ON client_license_view
BEGIN
    DELETE FROM client_license
    WHERE app_id=(SELECT app_id FROM app WHERE name=OLD.app_name) AND uid=OLD.uid;
END;

COMMIT TRANSACTION;
