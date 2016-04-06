BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 6;

CREATE TABLE app_new (
    app_id INTEGER PRIMARY KEY,
    pkg_id INTEGER NOT NULL,
    name VARCHAR NOT NULL,
    version VARCHAR NOT NULL,
    UNIQUE (name),
    FOREIGN KEY (pkg_id) REFERENCES pkg (pkg_id)
);

CREATE TABLE user_app (
    app_id INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    PRIMARY KEY (app_id, uid),
    FOREIGN KEY (app_id) REFERENCES app (app_id)
);

INSERT INTO user_app SELECT app_id, uid FROM app;
INSERT INTO app_new  SELECT app_id, pkg_id, name, version FROM app;
DROP TABLE app;
ALTER TABLE app_new RENAME TO app;

COMMIT TRANSACTION;
