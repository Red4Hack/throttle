-- Throttle schema v1.
--
-- Conventions:
--   * Timestamps are unix seconds (INTEGER, UTC).
--   * `ip` is the raw address (4 or 16 bytes), never text.
--   * Steam IDs are stored as INTEGER (SteamID64 is < 2^63, so it fits i64).
--   * Memory addresses/offsets are TEXT ("0x...") to avoid signed/unsigned
--     surprises; the old schema used 32-bit columns, which cannot hold 64-bit
--     dumps.
--   * `crash.status`: 0 = pending, 1 = processing, 2 = done, 3 = failed.
--     The pending set IS the work queue (ordered FIFO by created_at).

CREATE TABLE crash (
    id             TEXT    PRIMARY KEY CHECK (length(id) = 12),
    created_at     INTEGER NOT NULL,
    ip             BLOB    NOT NULL,
    owner          INTEGER,
    server_id      TEXT,
    metadata       TEXT    NOT NULL DEFAULT '{}',   -- JSON object
    cmdline        TEXT,
    status         INTEGER NOT NULL DEFAULT 0 CHECK (status IN (0, 1, 2, 3)),
    attempts       INTEGER NOT NULL DEFAULT 0,
    has_dump       INTEGER NOT NULL DEFAULT 1,      -- 0 = metadata-only upload
    dump_bytes     INTEGER NOT NULL DEFAULT 0,
    thread         INTEGER,
    stackhash      TEXT,
    signature      TEXT,                            -- presubmit hash (module+offset of top frames), for dedupe
    crash_module   TEXT,
    crash_function TEXT,
    last_view      INTEGER,
    processed_at   INTEGER,
    error          TEXT,                            -- why processing failed (status 3)
    sys_error      TEXT                             -- text of an engine Sys_Error abort
) STRICT;

CREATE INDEX crash_by_created ON crash (created_at);
CREATE INDEX crash_by_owner   ON crash (owner, created_at);
CREATE INDEX crash_by_ip      ON crash (ip, created_at);
CREATE INDEX crash_by_status  ON crash (status, created_at);
CREATE INDEX crash_by_hash    ON crash (stackhash);
CREATE INDEX crash_by_signature ON crash (signature, created_at);
CREATE INDEX crash_by_last_view ON crash (last_view) WHERE last_view IS NOT NULL;

-- Only the crashing thread and thread 0 are kept (same as the PHP version).
CREATE TABLE frame (
    crash    TEXT    NOT NULL REFERENCES crash (id) ON DELETE CASCADE,
    thread   INTEGER NOT NULL,
    frame    INTEGER NOT NULL,
    module   TEXT    NOT NULL DEFAULT '',
    function TEXT    NOT NULL DEFAULT '',
    file     TEXT    NOT NULL DEFAULT '',
    line     INTEGER NOT NULL DEFAULT 0,
    offset   TEXT    NOT NULL DEFAULT '',            -- "0x..."
    rendered TEXT    NOT NULL,
    url      TEXT,
    PRIMARY KEY (crash, thread, frame)
) STRICT, WITHOUT ROWID;

CREATE INDEX frame_by_module_function ON frame (module, function) WHERE frame = 0;

CREATE TABLE module (
    crash      TEXT    NOT NULL REFERENCES crash (id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    identifier TEXT    NOT NULL,
    base       TEXT,                                 -- "0x..."
    present    INTEGER NOT NULL DEFAULT 0,           -- symbols were available when processed
    PRIMARY KEY (crash, name, identifier)
) STRICT, WITHOUT ROWID;

CREATE INDEX module_by_symbol ON module (name, identifier);

-- Symbol files we hold. Presubmit checks this table (one lookup per module)
-- instead of touching the filesystem.
CREATE TABLE symbol (
    name       TEXT    NOT NULL,
    identifier TEXT    NOT NULL,
    store      TEXT    NOT NULL DEFAULT 'public',    -- subdirectory under symbols/
    bytes      INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (name, identifier, store)
) STRICT, WITHOUT ROWID;

CREATE TABLE user (
    id          INTEGER PRIMARY KEY,                 -- SteamID64
    name        TEXT,
    avatar      TEXT,
    updated_at  INTEGER,
    last_active INTEGER
) STRICT;

CREATE TABLE share (
    owner       INTEGER NOT NULL REFERENCES user (id) ON DELETE CASCADE,
    user        INTEGER NOT NULL REFERENCES user (id) ON DELETE CASCADE,
    invited_at  INTEGER NOT NULL,
    accepted_at INTEGER,
    PRIMARY KEY (owner, user),
    CHECK (owner <> user)
) STRICT, WITHOUT ROWID;

CREATE INDEX share_by_user ON share (user);

-- Declarative notice rules. Replaces the old `notice.rule`, which held raw SQL
-- that was concatenated into a UNION query.
--   rule: JSON, e.g. {"frame0_module": "engine*.so", "frame0_function": "Sys_Error*"}
--   (evaluated in Rust; never executed as SQL)
CREATE TABLE notice (
    id       TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    text     TEXT NOT NULL,
    rule     TEXT NOT NULL
) STRICT;

CREATE TABLE crashnotice (
    crash  TEXT NOT NULL REFERENCES crash (id)  ON DELETE CASCADE,
    notice TEXT NOT NULL REFERENCES notice (id) ON DELETE CASCADE,
    PRIMARY KEY (crash, notice)
) STRICT, WITHOUT ROWID;

-- Hourly counters; replaces Redis HINCRBY + munin/rrdtool.
CREATE TABLE counter (
    bucket INTEGER NOT NULL,                         -- unix time rounded down to the hour
    name   TEXT    NOT NULL,
    value  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, name)
) STRICT, WITHOUT ROWID;

-- Modules no symbol server had, so they are not asked for on every pass.
CREATE TABLE symbol_miss (
    name       TEXT    NOT NULL,
    identifier TEXT    NOT NULL,
    tried_at   INTEGER NOT NULL,
    PRIMARY KEY (name, identifier)
) STRICT, WITHOUT ROWID;

CREATE INDEX module_missing_symbols ON module (name, identifier) WHERE present = 0;
