PRAGMA journal_mode = PERSIST;
PRAGMA foreign_keys = ON;
PRAGMA auto_vacuum = NONE;

BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 0;

CREATE TABLE IF NOT EXISTS pkg (
pkg_id INTEGER PRIMARY KEY,
name VARCHAR NOT NULL,
UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS app (
app_id INTEGER PRIMARY KEY,
pkg_id INTEGER NOT NULL,
uid INTEGER NOT NULL,
name VARCHAR NOT NULL,
version VARCHAR NOT NULL,
author_id INTEGER,
UNIQUE (name, uid),
FOREIGN KEY (pkg_id) REFERENCES pkg (pkg_id)
FOREIGN KEY (author_id) REFERENCES author (author_id)
);

CREATE TABLE IF NOT EXISTS privilege (
privilege_id INTEGER PRIMARY KEY,
name VARCHAR NOT NULL,
UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS version (
version_id INTEGER PRIMARY KEY,
name VARCHAR NOT NULL,
UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS app_privilege (
app_id INTEGER NOT NULL,
privilege_id INTEGER NOT NULL ,
PRIMARY KEY (app_id, privilege_id),
FOREIGN KEY (app_id) REFERENCES app (app_id)
FOREIGN KEY (privilege_id) REFERENCES privilege (privilege_id)
);

CREATE TABLE IF NOT EXISTS shared_path (
path_id INTEGER PRIMARY KEY,
path VARCHAR NOT NULL,
path_label VARCHAR NOT NULL,
UNIQUE (path)
);

CREATE TABLE IF NOT EXISTS app_private_sharing (
owner_app_id INTEGER NOT NULL,
target_app_id INTEGER NOT NULL,
path_id INTEGER NOT NULL,
counter INTEGER NOT NULL,
PRIMARY KEY (owner_app_id, target_app_id, path_id)
FOREIGN KEY (owner_app_id) REFERENCES app (app_id)
FOREIGN KEY (target_app_id) REFERENCES app (app_id)
FOREIGN KEY (path_id) REFERENCES shared_path (path_id)
);

CREATE TABLE IF NOT EXISTS privilege_group (
privilege_id INTEGER NOT NULL,
group_name VARCHAR NOT NULL,
PRIMARY KEY (privilege_id, group_name),
FOREIGN KEY (privilege_id) REFERENCES privilege (privilege_id)
);

CREATE TABLE IF NOT EXISTS author (
	author_id INTEGER PRIMARY KEY,
	name VARCHAR NOT NULL,
	UNIQUE (name)
);

DROP VIEW IF EXISTS app_privilege_view;
CREATE VIEW app_privilege_view AS
SELECT
	app_privilege.app_id as app_id,
	app.name as app_name,
	app.uid as uid,
	app.pkg_id as pkg_id,
	pkg.name as pkg_name,
	app_privilege.privilege_id as privilege_id,
	privilege.name as privilege_name
FROM app_privilege
LEFT JOIN app USING (app_id)
LEFT JOIN pkg USING (pkg_id)
LEFT JOIN privilege USING (privilege_id);

DROP VIEW IF EXISTS app_pkg_view;
CREATE VIEW app_pkg_view AS
SELECT
    app.app_id,
    app.name as app_name,
    app.pkg_id,
    app.uid,
    pkg.name as pkg_name,
    app.version as version,
    app.author_id,
    author.name as author_name
FROM app
LEFT JOIN pkg USING (pkg_id)
LEFT JOIN author USING (author_id);

DROP TRIGGER IF EXISTS app_privilege_view_insert_trigger;
CREATE TRIGGER app_privilege_view_insert_trigger
INSTEAD OF INSERT ON app_privilege_view
BEGIN
	INSERT OR IGNORE INTO privilege(name) VALUES (NEW.privilege_name);
	INSERT OR IGNORE INTO app_privilege(app_id, privilege_id) VALUES
		((SELECT app_id FROM app WHERE name=NEW.app_name AND uid=NEW.uid),
		 (SELECT privilege_id FROM privilege WHERE name=NEW.privilege_name));
END;

DROP TRIGGER IF EXISTS app_privilege_view_delete_trigger;
CREATE TRIGGER app_privilege_view_delete_trigger
INSTEAD OF DELETE ON app_privilege_view
BEGIN
	DELETE FROM app_privilege WHERE app_id=OLD.app_id AND privilege_id=OLD.privilege_id;
END;

DROP TRIGGER IF EXISTS app_pkg_view_insert_trigger;
CREATE TRIGGER app_pkg_view_insert_trigger
INSTEAD OF INSERT ON app_pkg_view
BEGIN
    INSERT OR IGNORE INTO author(name) VALUES (NEW.author_name);
    INSERT OR IGNORE INTO pkg(name) VALUES (NEW.pkg_name);
    INSERT OR IGNORE INTO app(pkg_id, name, uid, version, author_id) VALUES (
        (SELECT pkg_id FROM pkg WHERE name=NEW.pkg_name),
        NEW.app_name,
        NEW.uid,
        NEW.version,
        (SELECT author_id FROM author WHERE name=NEW.author_name));
END;

DROP TRIGGER IF EXISTS app_pkg_view_delete_trigger;
CREATE TRIGGER app_pkg_view_delete_trigger
INSTEAD OF DELETE ON app_pkg_view
BEGIN
    DELETE FROM app WHERE app_id=OLD.app_id AND uid=OLD.uid;
    DELETE FROM pkg WHERE pkg_id NOT IN (SELECT DISTINCT pkg_id from app);
END;

DROP VIEW IF EXISTS app_private_sharing_view;
CREATE VIEW app_private_sharing_view AS
SELECT
    app1.name AS owner_app_name,
    app2.name AS target_app_name,
    path,
    path_label,
    counter
FROM app_private_sharing
LEFT JOIN app AS app1 ON app1.app_id = owner_app_id
LEFT JOIN app AS app2 ON app2.app_id = target_app_id
LEFT JOIN shared_path USING (path_id);

DROP TRIGGER IF EXISTS app_private_sharing_view_insert_trigger;
CREATE TRIGGER app_private_sharing_view_insert_trigger
INSTEAD OF INSERT ON app_private_sharing_view
BEGIN
    INSERT OR IGNORE INTO shared_path(path, path_label) VALUES (NEW.path, NEW.path_label);
    INSERT OR REPLACE INTO app_private_sharing VALUES (
            (SELECT app_id FROM app WHERE NEW.owner_app_name = name),
            (SELECT app_id FROM app WHERE NEW.target_app_name = name),
            (SELECT path_id FROM shared_path WHERE NEW.path = path),
            COALESCE((SELECT counter FROM app_private_sharing
                      WHERE target_app_id = (SELECT app_id FROM app
                                             WHERE NEW.target_app_name = name)
                      AND path_id = (SELECT path_id FROM shared_path WHERE NEW.path = path)),
                     0) + 1);
END;

DROP TRIGGER IF EXISTS app_private_sharing_view_remove_delete_trigger;
CREATE TRIGGER app_private_sharing_view_remove_delete_trigger
INSTEAD OF DELETE ON app_private_sharing_view
WHEN OLD.counter = 1
BEGIN
    DELETE FROM app_private_sharing
    WHERE path_id = (SELECT path_id FROM shared_path WHERE path = OLD.path)
    AND target_app_id = (SELECT app_id FROM app WHERE name = OLD.target_app_name);
    DELETE FROM shared_path WHERE path_id NOT IN (SELECT path_id FROM app_private_sharing) AND path = OLD.path;
END;

DROP TRIGGER IF EXISTS app_private_sharing_view_decrement_delete_trigger;
CREATE TRIGGER app_private_sharing_view_decrement_delete_trigger
INSTEAD OF DELETE ON app_private_sharing_view
WHEN OLD.counter > 1
BEGIN
    UPDATE app_private_sharing SET counter = OLD.counter - 1
    WHERE target_app_id = (SELECT app_id FROM app WHERE name = OLD.target_app_name)
    AND path_id = (SELECT path_id FROM shared_path WHERE path = OLD.path);
END;

DROP VIEW IF EXISTS privilege_group_view;
CREATE VIEW privilege_group_view AS
SELECT
    privilege_id,
    privilege.name as privilege_name,
    privilege_group.group_name
FROM privilege_group
LEFT JOIN privilege USING (privilege_id);

DROP TRIGGER IF EXISTS privilege_group_view_insert_trigger;
CREATE TRIGGER privilege_group_view_insert_trigger
INSTEAD OF INSERT ON privilege_group_view
BEGIN
    INSERT OR IGNORE INTO privilege(name) VALUES (NEW.privilege_name);
    INSERT OR IGNORE INTO privilege_group(privilege_id, group_name) VALUES ((SELECT privilege_id FROM privilege WHERE name=NEW.privilege_name), NEW.group_name);
END;

COMMIT TRANSACTION;
