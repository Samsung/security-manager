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
UNIQUE (name, uid),
FOREIGN KEY (pkg_id) REFERENCES pkg (pkg_id)
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

CREATE TABLE IF NOT EXISTS privilege_group (
privilege_id INTEGER NOT NULL,
group_name VARCHAR NOT NULL,
PRIMARY KEY (privilege_id, group_name),
FOREIGN KEY (privilege_id) REFERENCES privilege (privilege_id)
);

CREATE TABLE IF NOT EXISTS privilege_mapping (
version_from_id INTEGER NOT NULL,
privilege_id INTEGER NOT NULL,
version_to_id INTEGER NOT NULL,
privilege_mapping_id INTEGER NOT NULL,
PRIMARY KEY (version_from_id, privilege_id, version_to_id, privilege_mapping_id),
FOREIGN KEY (privilege_id) REFERENCES privilege (privilege_id)
FOREIGN KEY (version_from_id) REFERENCES version (version_id)
FOREIGN KEY (privilege_mapping_id) REFERENCES privilege (privilege_id)
FOREIGN KEY (version_to_id) REFERENCES version (version_id)
);

CREATE TABLE IF NOT EXISTS privilege_default_mapping (
version_from_id INTEGER NOT NULL,
version_to_id INTEGER NOT NULL,
privilege_mapping_id INTEGER NOT NULL,
PRIMARY KEY (version_from_id, version_to_id, privilege_mapping_id),
FOREIGN KEY (version_from_id) REFERENCES version (version_id)
FOREIGN KEY (privilege_mapping_id) REFERENCES privilege (privilege_id)
FOREIGN KEY (version_to_id) REFERENCES version (version_id)
);

CREATE TABLE IF NOT EXISTS privilege_to_map (
privilege_name VARCHAR
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
    app.version as version
FROM app
LEFT JOIN pkg USING (pkg_id);

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
    INSERT OR IGNORE INTO pkg(name) VALUES (NEW.pkg_name);
    INSERT OR IGNORE INTO app(pkg_id, name, uid, version) VALUES ((SELECT pkg_id FROM pkg WHERE name=NEW.pkg_name), NEW.app_name, NEW.uid, NEW.version);
END;

DROP TRIGGER IF EXISTS app_pkg_view_delete_trigger;
CREATE TRIGGER app_pkg_view_delete_trigger
INSTEAD OF DELETE ON app_pkg_view
BEGIN
    DELETE FROM app WHERE app_id=OLD.app_id AND uid=OLD.uid;
    DELETE FROM pkg WHERE pkg_id NOT IN (SELECT DISTINCT pkg_id from app);
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

DROP VIEW IF EXISTS privilege_mapping_view;
CREATE VIEW privilege_mapping_view AS
SELECT
        version1.name AS version_from_name,
        version2.name AS version_to_name,
        privilege1.name AS privilege_name,
        privilege2.name AS privilege_mapping_name
FROM privilege_mapping
LEFT JOIN privilege AS privilege1 ON privilege_mapping.privilege_id = privilege1.privilege_id
LEFT JOIN privilege AS privilege2 ON privilege_mapping.privilege_mapping_id = privilege2.privilege_id
LEFT JOIN version AS version1 ON privilege_mapping.version_from_id = version1.version_id
LEFT JOIN version AS version2 ON privilege_mapping.version_to_id = version2.version_id
UNION
SELECT
        version1.name AS version_from_name,
        version2.name AS version_to_name,
        NULL AS privilege_name,
        privilege2.name AS privilege_mapping_name
FROM privilege_default_mapping
LEFT JOIN privilege AS privilege2 ON privilege_default_mapping.privilege_mapping_id = privilege2.privilege_id
LEFT JOIN version AS version1 ON privilege_default_mapping.version_from_id = version1.version_id
LEFT JOIN version AS version2 ON privilege_default_mapping.version_to_id = version2.version_id;

DROP TRIGGER IF EXISTS privilege_mapping_insert_trigger;
CREATE TRIGGER privilege_mapping_insert_trigger
INSTEAD OF INSERT ON privilege_mapping_view
WHEN (NEW.privilege_name IS NOT NULL)
BEGIN
        INSERT OR IGNORE INTO privilege(name) VALUES (NEW.privilege_name);
        INSERT OR IGNORE INTO privilege(name) VALUES (NEW.privilege_mapping_name);
        INSERT OR IGNORE INTO version(name) VALUES (NEW.version_from_name);
        INSERT OR IGNORE INTO version(name) VALUES (NEW.version_to_name);
        INSERT OR IGNORE INTO privilege_mapping(privilege_id, version_from_id, privilege_mapping_id, version_to_id) VALUES
            ((SELECT privilege_id FROM privilege WHERE name=NEW.privilege_name),
             (SELECT version_id FROM version WHERE name=NEW.version_from_name),
             (SELECT privilege_id FROM privilege WHERE name=NEW.privilege_mapping_name),
             (SELECT version_id FROM version WHERE name=NEW.version_to_name));
END;

DROP TRIGGER IF EXISTS privilege_default_mapping_insert_trigger;
CREATE TRIGGER privilege_default_mapping_insert_trigger
INSTEAD OF INSERT ON privilege_mapping_view
WHEN (NEW.privilege_name IS NULL)
BEGIN
        INSERT OR IGNORE INTO privilege(name) VALUES (NEW.privilege_mapping_name);
        INSERT OR IGNORE INTO version(name) VALUES (NEW.version_from_name);
        INSERT OR IGNORE INTO version(name) VALUES (NEW.version_to_name);
        INSERT OR IGNORE INTO privilege_default_mapping(version_from_id, privilege_mapping_id, version_to_id) VALUES
            ((SELECT version_id FROM version WHERE name=NEW.version_from_name),
             (SELECT privilege_id FROM privilege WHERE name=NEW.privilege_mapping_name),
             (SELECT version_id FROM version WHERE name=NEW.version_to_name));
END;
COMMIT TRANSACTION;
