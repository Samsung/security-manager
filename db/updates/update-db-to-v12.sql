PRAGMA foreign_keys=OFF;

BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 12;

CREATE TABLE app_defined_privilege_new (
app_id INTEGER NOT NULL,
uid INTEGER NOT NULL,
privilege VARCHAR NOT NULL,
type INTEGER NOT NULL CHECK (type >= 0 AND type <= 1),
license VARCHAR,
UNIQUE (uid, privilege),
FOREIGN KEY (app_id, uid) REFERENCES user_app (app_id, uid) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE client_license_new (
app_id INTEGER NOT NULL,
uid INTEGER NOT NULL,
privilege VARCHAR NOT NULL,
license VARCHAR NOT NULL,
UNIQUE (app_id, uid, privilege),
FOREIGN KEY(app_id, uid) REFERENCES user_app (app_id, uid) ON UPDATE CASCADE ON DELETE CASCADE
);

INSERT INTO app_defined_privilege_new
SELECT app_id, uid, privilege, type, license
FROM app_defined_privilege;

INSERT INTO client_license_new
SELECT app_id, uid, privilege, license
FROM client_license;

DROP TABLE app_defined_privilege;
DROP TABLE client_license;

ALTER TABLE app_defined_privilege_new RENAME TO app_defined_privilege;
ALTER TABLE client_license_new RENAME TO client_license;

PRAGMA foreign_key_check;

COMMIT TRANSACTION;

PRAGMA foreign_keys=ON;
