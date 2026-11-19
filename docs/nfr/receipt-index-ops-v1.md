# Receipt index operational note - crash-resilient schema migration (NFR operability, J2)

**Scope and honesty rules.** This note covers the receipt index
(`raucle/receipt_index.py`), the SQLite projection over the chain of
record. Everything here was verified live against the code and its
test suite (`tests/test_receipt_index.py`, `TestMigrationCrashRecovery`);
the SQLite behaviour claims (DDL and `PRAGMA user_version` are
transactional) were probed directly on SQLite 3.53.1. The index makes
no compliance claims and holds no trust decision: verification always
reads the chain, never the index. This note is operational doctrine, so
it must be updated, not contradicted, if a later migration weakens any
invariant named below.

## What the index is (the contract that makes recovery safe)

- The index is a QUERY CACHE over the segmented receipt chain: it can
  be dropped and rebuilt at any time (`rebuild_from_store`). The chain
  of record on disk is the tamper-evident truth; the index only
  accelerates queries.
- Because the projection is derivable, a half-migrated index is an
  OPERATIONS problem, never a data-loss event. The worst an
  interrupted migration can do is force a rebuild. Recovery doctrine
  follows: a half-migrated projection must resume or rebuild itself,
  never crash-loop a boot.

## The incident (worked example, 18 Nov 2026 demo environment)

During the 18 Nov demonstration the gateway process was OOM-killed
three times at 23.4 GB RSS, the kills landing during the receipt index
migrate-on-open (schema v1/v2 to v3). That migration ran as separate
autocommitted statements:

1. `ALTER TABLE receipts RENAME TO receipts_prev_backup` - durable the
   moment it ran.
2. `CREATE TABLE receipts (...)` - durable.
3. `INSERT ... SELECT` copy of the backup rows into the new table -
   transactional, committed only later.
4. `DROP TABLE receipts_prev_backup` - transactional with 3.
5. `PRAGMA user_version = 3` - transactional with 3 and 4.

A kill between step 2 and the commit of step 3 left the file with the
backup table beside an EMPTY live table at the old version. Every later
boot re-entered the migration and died at step 1 with:

    sqlite3.OperationalError: there is already another table or index
    with this name: receipts_prev_backup

Under `restart:always` this is a permanent crash-loop: the store never
boots, and the operator has no named recovery. The chain of record was
never at risk - only the projection.

Operator recovery before the fix, for the record: stop the gateway,
then either delete the index file (the gateway rebuilds the projection
from the chain on the next boot, while the index is empty) or drop one
of the two tables with the sqlite3 CLI. Both work precisely because the
index is a rebuildable projection. After the fix neither is needed.

## The fix (J2)

Two changes, red-first tested:

1. Recovery before the ALTER. On open, the index inspects the schema
   for the interrupted-migration artifact (`receipts_prev_backup`
   present). Inspection happens BEFORE any ALTER runs; the rename
   error is never caught after the fact. Recovery states, and the
   ordering that cannot lose projected data:

   - Backup WITHOUT a live table: the crash landed between the rename
     and the re-create. Undo the rename - the backup is all the
     projection there is - stamp `user_version` 0 (the restored shape
     predates the interrupted attempt, so the version row must not
     claim a migration the schema did not get) and let the normal
     migration re-run from a known state.
   - Backup WITH a live table at the current version: a completed
     migration drops the backup and stamps the version in one
     transaction, so this is a stale leftover the fixed code cannot
     produce. The current live table is authoritative; the backup is
     dropped.
   - Backup WITH a half-built live table at an older version (the
     observed signature): the half-built table only ever received rows
     copied FROM the backup (the store never finished booting, so no
     other writer touched it), so its rows are a subset of the
     backup's. Recovery drops the half-built table, completes the
     interrupted migration by re-copying from the backup, drops the
     backup only after its rows are re-copied, and stamps the version
     - one committed transaction.

   The backup is treated as the authoritative snapshot because the
   rename that created it was the migration's first durable step; it is
   never dropped before its rows exist elsewhere in the same committed
   transaction. Recovery prefers completing the interrupted rename over
   a cold chain rebuild because the index constructor has no store
   reference (the gateway feeds and rebuilds after construction); the
   chain remains the backstop, and a recovered index still passes a
   full projection rebuild verification against it.

2. One transaction per migration. The migration, its index definitions
   and the `user_version` stamp now commit as ONE explicit transaction.
   SQLite DDL and `PRAGMA user_version` are transactional
   (probe-verified on 3.53.1), so a crash at ANY step rolls the file
   back to the pristine pre-migration state and the next open simply
   re-runs the migration. The fixed code can no longer produce a
   half-migrated file; recovery exists for the files the previous
   autocommitting implementation left behind.

Every recovery branch logs one named, greppable line:

    receipt_index: recovered interrupted schema migration (<action>):
    <n> projected rows preserved at <path>

## The migration journal (the schema version rows)

There is no separate journal table: the schema version rows carry the
journal. Invariants, enforced by the transaction shape and pinned by
tests:

- `user_version` advances ONLY inside the same transaction that
  produces the new schema shape, so the version row never claims a
  migration the schema did not get.
- A crash at any step leaves either the fully pre-migration state or
  the fully migrated state; both re-open cleanly, and the pre state
  re-runs the migration.
- The only half-states are artifacts of the pre-transaction
  implementation or of writes from outside this code; they are
  detected by schema inspection and recovered deterministically.
- Recovery itself is one idempotent transaction: a crash during it
  rolls back to the same detected state and the same branch re-runs.
- A future migration that CANNOT be a single transaction (for example
  a backfill too large for one commit) must extend this note with
  step-journal rows before it ships. The single-transaction invariant
  is the load-bearing guarantee; it must not be weakened silently.

## Residual risks (honest register)

- The OOM itself. This fix removes the crash-loop, not the memory
  pressure: a store that OOM-dies at 23.4 GB RSS will keep dying (and,
  now, keep recovering) until the boot memory ceiling lands. That work
  is J1, out of scope here.
- The index rotation command (vacuum or rotation for very large index
  files) does not exist yet; J1 owns that gap.
- A file damaged below the SQLite layer (torn writes on storage that
  ignores fsync, with `synchronous=NORMAL`) can still fail to open.
  SQLite's WAL recovery handles process kills; it does not handle disk
  corruption. Deleting the index file and letting the gateway rebuild
  from the chain is the operator path there, as before.
- Recovery trusts the backup table's rows as PROJECTED data, not as
  truth. A tampered index never affects verification (the chain is
  the truth); `rebuild_from_store` remains the repair path for a
  projection an operator does not trust.
