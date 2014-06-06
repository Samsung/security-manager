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
name VARCHAR NOT NULL ,
UNIQUE (name),
FOREIGN KEY (pkg_id) REFERENCES pkg (pkg_id)
);

CREATE TABLE IF NOT EXISTS permission (
permission_id INTEGER PRIMARY KEY,
name VARCHAR NOT NULL ,
UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS app_permission (
app_id INTEGER NOT NULL,
permission_id INTEGER NOT NULL ,
PRIMARY KEY (app_id, permission_id),
FOREIGN KEY (app_id) REFERENCES app (app_id)
FOREIGN KEY (permission_id) REFERENCES permission (permission_id)
);

CREATE TABLE IF NOT EXISTS permission_gid (
permission_id INTEGER NOT NULL,
gid INTEGER NOT NULL,
PRIMARY KEY (permission_id, gid),
FOREIGN KEY (permission_id) REFERENCES permission (permission_id)
);

DROP VIEW IF EXISTS app_permission_view;
CREATE VIEW app_permission_view AS
SELECT
	app_permission.app_id as app_id,
	app.name as app_name,
	app.pkg_id as pkg_id,
	pkg.name as pkg_name,
	app_permission.permission_id as permission_id,
	permission.name as permission_name
FROM app_permission
LEFT JOIN app USING (app_id)
LEFT JOIN pkg USING (pkg_id)
LEFT JOIN permission USING (permission_id);

DROP VIEW IF EXISTS app_pkg_view;
CREATE VIEW app_pkg_view AS
SELECT
    app.app_id,
    app.name as app_name,
    app.pkg_id,
    pkg.name as pkg_name
FROM app
LEFT JOIN pkg USING (pkg_id);

DROP TRIGGER IF EXISTS app_permission_view_insert_trigger;
CREATE TRIGGER app_permission_view_insert_trigger
INSTEAD OF INSERT ON app_permission_view
BEGIN
	INSERT OR IGNORE INTO pkg(name) VALUES (NEW.pkg_name);
	INSERT OR IGNORE INTO permission(name) VALUES (NEW.permission_name);
	INSERT OR IGNORE INTO app(pkg_id, name) VALUES ((SELECT pkg_id FROM pkg WHERE name=NEW.pkg_name), NEW.app_name);
	INSERT OR IGNORE INTO app_permission(app_id, permission_id) VALUES
		((SELECT app_id FROM app WHERE name=NEW.app_name), (SELECT permission_id FROM permission WHERE name=NEW.permission_name));
END;

DROP TRIGGER IF EXISTS app_permission_view_delete_trigger;
CREATE TRIGGER app_permission_view_delete_trigger
INSTEAD OF DELETE ON app_permission_view
BEGIN
	DELETE FROM app_permission WHERE app_id=OLD.app_id AND permission_id=OLD.permission_id;
END;

DROP TRIGGER IF EXISTS app_pkg_view_insert_trigger;
CREATE TRIGGER app_pkg_view_insert_trigger
INSTEAD OF INSERT ON app_pkg_view
BEGIN
    INSERT OR IGNORE INTO pkg(name) VALUES (NEW.pkg_name);
    INSERT OR IGNORE INTO app(pkg_id, name) VALUES ((SELECT pkg_id FROM pkg WHERE name=NEW.pkg_name), NEW.app_name);
END;

DROP TRIGGER IF EXISTS app_pkg_view_delete_trigger;
CREATE TRIGGER app_pkg_view_delete_trigger
INSTEAD OF DELETE ON app_pkg_view
BEGIN
    DELETE FROM app WHERE app_id=OLD.app_id AND pkg_id=OLD.pkg_id;
    DELETE FROM pkg WHERE pkg_id NOT IN (SELECT DISTINCT pkg_id from app);
END;

COMMIT TRANSACTION;
