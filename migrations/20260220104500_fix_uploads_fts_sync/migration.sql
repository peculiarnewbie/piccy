DROP TRIGGER IF EXISTS uploads_fts_insert;
DROP TRIGGER IF EXISTS uploads_fts_delete;
DROP TRIGGER IF EXISTS uploads_fts_update;

DROP TABLE IF EXISTS uploads_fts;

CREATE VIRTUAL TABLE uploads_fts USING fts5(
  id UNINDEXED,
  description
);

INSERT INTO uploads_fts(id, description)
SELECT id, description
FROM uploads
WHERE description IS NOT NULL
  AND deleted_at IS NULL;

CREATE TRIGGER uploads_fts_insert AFTER INSERT ON uploads
WHEN NEW.description IS NOT NULL
  AND NEW.deleted_at IS NULL
BEGIN
  INSERT INTO uploads_fts(id, description) VALUES (NEW.id, NEW.description);
END;

CREATE TRIGGER uploads_fts_update AFTER UPDATE OF description, deleted_at ON uploads
BEGIN
  DELETE FROM uploads_fts WHERE id = NEW.id;
  INSERT INTO uploads_fts(id, description)
  SELECT NEW.id, NEW.description
  WHERE NEW.description IS NOT NULL
    AND NEW.deleted_at IS NULL;
END;

CREATE TRIGGER uploads_fts_delete AFTER DELETE ON uploads
BEGIN
  DELETE FROM uploads_fts WHERE id = OLD.id;
END;
