BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 7;

ALTER TABLE pkg ADD shared_ro INTEGER NOT NULL DEFAULT 0;

UPDATE pkg
SET shared_ro = 1
WHERE pkg_id IN (SELECT pkg_id FROM app WHERE version < 3);

COMMIT TRANSACTION;