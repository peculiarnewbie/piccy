ALTER TABLE `uploads` ADD `description` text;

CREATE VIRTUAL TABLE IF NOT EXISTS uploads_fts USING fts5(
  id UNINDEXED,
  description,
  content='',
  contentless_delete=1
);

CREATE TRIGGER uploads_fts_insert AFTER UPDATE OF description ON uploads
WHEN NEW.description IS NOT NULL
BEGIN
  DELETE FROM uploads_fts WHERE id = NEW.id;
  INSERT INTO uploads_fts(id, description) VALUES (NEW.id, NEW.description);
END;

CREATE TRIGGER uploads_fts_delete AFTER UPDATE OF deleted_at ON uploads
WHEN NEW.deleted_at IS NOT NULL
BEGIN
  DELETE FROM uploads_fts WHERE id = OLD.id;
END;