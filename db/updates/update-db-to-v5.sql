BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 5;

CREATE TABLE privilege_group_new (
    privilege_name VARCHAR NOT NULL,
    group_name VARCHAR NOT NULL,
    PRIMARY KEY (privilege_name, group_name)
);

INSERT INTO privilege_group_new SELECT privilege_name, group_name FROM privilege_group_view;

DROP TABLE privilege_group;
ALTER TABLE privilege_group_new RENAME TO privilege_group;

DROP VIEW privilege_group_view;
DROP VIEW app_privilege_view;

DROP TABLE privilege;
DROP TABLE app_privilege;

COMMIT TRANSACTION;
