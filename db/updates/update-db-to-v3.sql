PRAGMA foreign_keys = OFF;
BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 3;

-- Tables
ALTER TABLE pkg ADD COLUMN author_id INTEGER REFERENCES author (author_id);

CREATE TABLE app_new (
app_id INTEGER PRIMARY KEY,
pkg_id INTEGER NOT NULL,
uid INTEGER NOT NULL,
name VARCHAR NOT NULL,
version VARCHAR NOT NULL,
UNIQUE (name, uid),
FOREIGN KEY (pkg_id) REFERENCES pkg (pkg_id)
);

INSERT INTO app_new SELECT app_id, pkg_id, uid, name, version FROM app;

-- TODO this will ignore all other authors of given pkg apps except 1st one. Maybe the migration should fail in such case?
UPDATE pkg SET author_id = (SELECT author_id FROM app_pkg_view WHERE author_id IS NOT NULL AND pkg_id = pkg.pkg_id);

DROP TABLE app;
ALTER TABLE app_new RENAME TO app;

COMMIT TRANSACTION;
PRAGMA foreign_keys = ON;
