use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use rusqlite::{OptionalExtension as _, params};

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS snapshots (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        saved_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS local_files (
        path TEXT PRIMARY KEY,
        parent TEXT NOT NULL,
        mtime INTEGER NOT NULL,
        size INTEGER NOT NULL,
        track TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS local_folders (
        path TEXT PRIMARY KEY,
        parent TEXT NOT NULL,
        mtime INTEGER NOT NULL,
        portrait TEXT
    );";

/// A key to text store for data the app can always fetch again. It lives in the cache directory
/// rather than in [`crate::Database`], so deleting it costs a reload and never a favorite, a play
/// or a playlist. Every call opens its own connection, which is what makes it safe to use from a
/// blocking thread.
#[derive(Clone)]
pub struct Cache {
    path: PathBuf,
    ready: Arc<Mutex<bool>>,
}

impl Cache {
    /// `$XDG_CACHE_HOME/sonora/cache.sqlite` and equivalent on Windows.
    pub fn standard() -> Self {
        let dir = dirs::cache_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("sonora");
        Self::at(dir.join("cache.sqlite"))
    }

    pub fn at(path: PathBuf) -> Self {
        Self {
            path,
            ready: Arc::new(Mutex::new(false)),
        }
    }

    pub fn read(&self, key: &str) -> Result<Option<String>> {
        let connection = self.open()?;
        connection
            .query_row(
                "SELECT value FROM snapshots WHERE key = ?",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .context("cannot read a cached value")
    }

    pub fn write(&self, key: &str, value: &str, saved_at: i64) -> Result<()> {
        let connection = self.open()?;
        connection
            .execute(
                "INSERT INTO snapshots (key, value, saved_at) VALUES (?, ?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, saved_at = excluded.saved_at",
                params![key, value, saved_at],
            )
            .context("cannot write a cached value")?;
        Ok(())
    }

    /// Drops every key under `prefix`, which is how a whole provider is forgotten at once.
    pub fn forget(&self, prefix: &str) -> Result<()> {
        let connection = self.open()?;
        connection
            .execute(
                "DELETE FROM snapshots WHERE key LIKE ? || '%'",
                params![prefix],
            )
            .context("cannot drop cached values")?;
        Ok(())
    }

    /// A connection with every cache table in place. The local scan index reaches for this
    /// directly, the way local playlists do with [`crate::Database`].
    pub fn open(&self) -> Result<rusqlite::Connection> {
        crate::connect(&self.path, SCHEMA, &self.ready, "the cache")
    }
}
