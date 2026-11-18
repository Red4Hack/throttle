-- Why the process died, as the dump says it (`SIGSEGV / SEGV_MAPERR` at an address),
-- and whether the stack had to be unwound from the return address on the stack
-- because the instruction pointer was not code (a call through a bad pointer).
ALTER TABLE crash ADD COLUMN crash_reason  TEXT;
ALTER TABLE crash ADD COLUMN crash_address TEXT;
ALTER TABLE crash ADD COLUMN bad_jump      INTEGER NOT NULL DEFAULT 0;
