-- Foreign-key enforcement was previously disabled, so remove orphaned rows
-- before relying on ON DELETE CASCADE for share authorization.
DELETE FROM shares WHERE user NOT IN (SELECT id FROM users);
