BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 2;

DROP TABLE version;

CREATE TABLE app_private_sharing_new (
    owner_app_name TEXT NOT NULL,
    target_app_name TEXT NOT NULL,
    path_id INTEGER NOT NULL,
    counter INTEGER NOT NULL,
    PRIMARY KEY (owner_app_name, target_app_name, path_id)
    FOREIGN KEY (path_id) REFERENCES shared_path (path_id)
);

INSERT INTO app_private_sharing_new
    SELECT owner_app_name, target_app_name, path_id, counter
    FROM app_private_sharing_view
    LEFT JOIN shared_path USING (path);

DROP TABLE app_private_sharing;
ALTER TABLE app_private_sharing_new RENAME TO app_private_sharing;

COMMIT TRANSACTION;
