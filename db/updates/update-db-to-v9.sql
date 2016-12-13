PRAGMA foreign_keys=OFF;

BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 9;

CREATE TABLE shared_path_new (
path_id INTEGER PRIMARY KEY,
path VARCHAR NOT NULL,
path_label VARCHAR NOT NULL,
owner_app_name TEXT NOT NULL,
UNIQUE (path)
);

CREATE TABLE app_private_sharing_new (
target_app_name TEXT NOT NULL,
path_id INTEGER NOT NULL,
counter INTEGER NOT NULL,
PRIMARY KEY (target_app_name, path_id)
FOREIGN KEY (path_id) REFERENCES shared_path (path_id)
);

INSERT INTO shared_path_new
SELECT shared_path.path_id, path, path_label, owner_app_name
FROM shared_path, app_private_sharing
WHERE shared_path.path_id = app_private_sharing.path_id;

INSERT INTO app_private_sharing_new
SELECT target_app_name, path_id, counter
FROM app_private_sharing;

DROP TABLE shared_path;
DROP TABLE app_private_sharing;

ALTER TABLE shared_path_new RENAME TO shared_path;
ALTER TABLE app_private_sharing_new RENAME TO app_private_sharing;

PRAGMA foreign_key_check;

COMMIT TRANSACTION;

PRAGMA foreign_keys=ON;
