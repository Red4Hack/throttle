-- The same crash again (same owner, same fingerprint, inside `limits.repeat_window_days`) is
-- counted on the crash already stored instead of storing another dump.
ALTER TABLE crash ADD COLUMN repeats        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE crash ADD COLUMN last_repeat_at INTEGER;
