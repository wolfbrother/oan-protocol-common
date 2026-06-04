// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Storage helpers for local OpenAgenet nodes.

use serde::{de::DeserializeOwned, Serialize};
use sqlx::{Executor, Pool, Postgres, Sqlite};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("sql error: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("unsupported database url scheme")]
    UnsupportedDatabaseUrl,
    #[error("database path is empty")]
    EmptyDatabasePath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseBackend {
    Sqlite,
    Postgres,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseConfig {
    backend: DatabaseBackend,
    url: String,
    path: Option<PathBuf>,
}

impl DatabaseConfig {
    pub fn parse(url: impl Into<String>) -> Result<Self, StorageError> {
        let url = url.into();
        if let Some(raw_path) = url
            .strip_prefix("sqlite://")
            .or_else(|| url.strip_prefix("sqlite:"))
        {
            if raw_path.is_empty() {
                return Err(StorageError::EmptyDatabasePath);
            }
            return Ok(Self {
                backend: DatabaseBackend::Sqlite,
                path: Some(PathBuf::from(raw_path)),
                url,
            });
        }
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            return Ok(Self {
                backend: DatabaseBackend::Postgres,
                path: None,
                url,
            });
        }
        Err(StorageError::UnsupportedDatabaseUrl)
    }

    pub fn backend(&self) -> DatabaseBackend {
        self.backend
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

#[derive(Clone, Debug)]
pub struct SqliteJsonStore {
    pool: Pool<Sqlite>,
}

#[derive(Clone, Debug)]
pub struct PostgresJsonStore {
    pool: Pool<Postgres>,
}

#[derive(Clone, Debug)]
pub enum DatabaseStore {
    Sqlite(SqliteJsonStore),
    Postgres(PostgresJsonStore),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeasedJob<T> {
    pub job_key: String,
    pub payload: T,
    pub attempt_count: i64,
}

impl SqliteJsonStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let config = DatabaseConfig::parse(url)?;
        if config.backend() != DatabaseBackend::Sqlite {
            return Err(StorageError::UnsupportedDatabaseUrl);
        }
        let path = config.path().ok_or(StorageError::EmptyDatabasePath)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let options = sqlx::sqlite::SqliteConnectOptions::from_str(config.url())?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(30));
        let max_connections = configured_pool_max_connections("OAN_SQLITE_MAX_CONNECTIONS", 32);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(30))
            .connect_with(options)
            .await?;
        ensure_json_records_sqlite(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    pub async fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.pool.execute(sql).await?;
        Ok(())
    }

    pub async fn ensure_leased_job_table(&self, table: &str) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {table} (
                job_key TEXT NOT NULL PRIMARY KEY,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TEXT,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#
        );
        self.pool.execute(sql.as_str()).await?;
        Ok(())
    }

    pub async fn enqueue_leased_job<T: Serialize>(
        &self,
        table: &str,
        job_key: &str,
        value: &T,
        next_attempt_at: &str,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let value_json = serde_json::to_string(value)?;
        let sql = format!(
            r#"
            INSERT INTO {table}(job_key, payload_json, status, attempt_count, lease_owner, lease_expires_at, next_attempt_at, last_error)
            VALUES (?, ?, 'ready', 0, NULL, NULL, ?, NULL)
            ON CONFLICT(job_key)
            DO UPDATE SET
                payload_json = excluded.payload_json,
                status = 'ready',
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = excluded.next_attempt_at,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            "#
        );
        sqlx::query(sql.as_str())
            .bind(job_key)
            .bind(value_json)
            .bind(next_attempt_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn lease_ready_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
        worker_id: &str,
        limit: i64,
        now: &str,
        lease_expires_at: &str,
    ) -> Result<Vec<LeasedJob<T>>, StorageError> {
        let table = validated_identifier(table)?;
        let select_sql = format!(
            r#"
            SELECT job_key, payload_json, attempt_count
            FROM {table}
            WHERE
                (
                    status = 'ready'
                    OR (status = 'retry-wait' AND next_attempt_at <= ?)
                    OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
                )
            ORDER BY next_attempt_at, created_at, job_key
            LIMIT ?
            "#
        );
        let update_sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'leased',
                lease_owner = ?,
                lease_expires_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE
                job_key = ?
                AND (
                    status = 'ready'
                    OR (status = 'retry-wait' AND next_attempt_at <= ?)
                    OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
                )
            "#
        );

        let mut tx = self.pool.begin().await?;
        let selected = sqlx::query_as::<_, (String, String, i64)>(select_sql.as_str())
            .bind(now)
            .bind(now)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
        let mut leased = Vec::new();
        for (job_key, payload_json, attempt_count) in selected {
            let result = sqlx::query(update_sql.as_str())
                .bind(worker_id)
                .bind(lease_expires_at)
                .bind(&job_key)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() == 0 {
                continue;
            }
            leased.push(LeasedJob {
                job_key,
                payload: serde_json::from_str(&payload_json)?,
                attempt_count,
            });
        }
        tx.commit().await?;
        Ok(leased)
    }

    pub async fn mark_leased_job_succeeded(
        &self,
        table: &str,
        job_key: &str,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'succeeded',
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = ?
            "#
        );
        sqlx::query(sql.as_str())
            .bind(job_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_leased_job_retry(
        &self,
        table: &str,
        job_key: &str,
        next_attempt_at: &str,
        last_error: Option<&str>,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'retry-wait',
                attempt_count = attempt_count + 1,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = ?,
                last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = ?
            "#
        );
        sqlx::query(sql.as_str())
            .bind(next_attempt_at)
            .bind(last_error)
            .bind(job_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn read_active_leased_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
    ) -> Result<Vec<T>, StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            SELECT payload_json
            FROM {table}
            WHERE status IN ('ready', 'leased', 'retry-wait')
            ORDER BY updated_at, job_key
            "#
        );
        let rows = sqlx::query_as::<_, (String,)>(sql.as_str())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn read_ready_leased_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
        now: &str,
    ) -> Result<Vec<T>, StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            SELECT payload_json
            FROM {table}
            WHERE
                status = 'ready'
                OR (status = 'retry-wait' AND next_attempt_at <= ?)
                OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
            ORDER BY next_attempt_at, created_at, job_key
            "#
        );
        let rows = sqlx::query_as::<_, (String,)>(sql.as_str())
            .bind(now)
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn upsert_json<T: Serialize>(
        &self,
        namespace: &str,
        key: &str,
        value: &T,
    ) -> Result<(), StorageError> {
        let value_json = serde_json::to_string(value)?;
        sqlx::query(
            r#"
            INSERT INTO json_records(namespace, record_key, value_json)
            VALUES (?, ?, ?)
            ON CONFLICT(namespace, record_key)
            DO UPDATE SET value_json = excluded.value_json, updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(namespace)
        .bind(key)
        .bind(value_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn read_namespace<T: DeserializeOwned>(
        &self,
        namespace: &str,
    ) -> Result<Vec<T>, StorageError> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT value_json FROM json_records WHERE namespace = ? ORDER BY updated_at, record_key",
        )
        .bind(namespace)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn read_json<T: DeserializeOwned>(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT value_json FROM json_records WHERE namespace = ? AND record_key = ?",
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .transpose()
    }

    pub async fn delete_json(&self, namespace: &str, key: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM json_records WHERE namespace = ? AND record_key = ?")
            .bind(namespace)
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn count_namespace(&self, namespace: &str) -> Result<i64, StorageError> {
        let (count,) =
            sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM json_records WHERE namespace = ?")
                .bind(namespace)
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }

    pub async fn delete_namespace(&self, namespace: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM json_records WHERE namespace = ?")
            .bind(namespace)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl PostgresJsonStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let config = DatabaseConfig::parse(url)?;
        if config.backend() != DatabaseBackend::Postgres {
            return Err(StorageError::UnsupportedDatabaseUrl);
        }
        let max_connections = configured_pool_max_connections("OAN_POSTGRES_MAX_CONNECTIONS", 32);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(30))
            .connect(config.url())
            .await?;
        ensure_json_records_postgres(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    pub async fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.pool.execute(sql).await?;
        Ok(())
    }

    pub async fn ensure_leased_job_table(&self, table: &str) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {table} (
                job_key TEXT NOT NULL PRIMARY KEY,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count BIGINT NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TIMESTAMPTZ,
                next_attempt_at TIMESTAMPTZ NOT NULL,
                last_error TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_{table}_status_schedule
            ON {table}(status, next_attempt_at, lease_expires_at, job_key);
            "#
        );
        self.pool.execute(sql.as_str()).await?;
        Ok(())
    }

    pub async fn enqueue_leased_job<T: Serialize>(
        &self,
        table: &str,
        job_key: &str,
        value: &T,
        next_attempt_at: &str,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let value_json = serde_json::to_string(value)?;
        let sql = format!(
            r#"
            INSERT INTO {table}(job_key, payload_json, status, attempt_count, lease_owner, lease_expires_at, next_attempt_at, last_error)
            VALUES ($1, $2, 'ready', 0, NULL, NULL, $3::timestamptz, NULL)
            ON CONFLICT(job_key)
            DO UPDATE SET
                payload_json = excluded.payload_json,
                status = 'ready',
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = excluded.next_attempt_at,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            "#
        );
        sqlx::query(sql.as_str())
            .bind(job_key)
            .bind(value_json)
            .bind(next_attempt_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn lease_ready_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
        worker_id: &str,
        limit: i64,
        now: &str,
        lease_expires_at: &str,
    ) -> Result<Vec<LeasedJob<T>>, StorageError> {
        let table = validated_identifier(table)?;
        let select_sql = format!(
            r#"
            SELECT job_key, payload_json, attempt_count
            FROM {table}
            WHERE
                (
                    status = 'ready'
                    OR (status = 'retry-wait' AND next_attempt_at <= $1::timestamptz)
                    OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= $1::timestamptz)
                )
            ORDER BY next_attempt_at, created_at, job_key
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            "#
        );
        let update_sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'leased',
                lease_owner = $1,
                lease_expires_at = $2::timestamptz,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = $3
            "#
        );

        let mut tx = self.pool.begin().await?;
        let selected = sqlx::query_as::<_, (String, String, i64)>(select_sql.as_str())
            .bind(now)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
        let mut leased = Vec::new();
        for (job_key, payload_json, attempt_count) in selected {
            sqlx::query(update_sql.as_str())
                .bind(worker_id)
                .bind(lease_expires_at)
                .bind(&job_key)
                .execute(&mut *tx)
                .await?;
            leased.push(LeasedJob {
                job_key,
                payload: serde_json::from_str(&payload_json)?,
                attempt_count,
            });
        }
        tx.commit().await?;
        Ok(leased)
    }

    pub async fn mark_leased_job_succeeded(
        &self,
        table: &str,
        job_key: &str,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'succeeded',
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = $1
            "#
        );
        sqlx::query(sql.as_str())
            .bind(job_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_leased_job_retry(
        &self,
        table: &str,
        job_key: &str,
        next_attempt_at: &str,
        last_error: Option<&str>,
    ) -> Result<(), StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            UPDATE {table}
            SET
                status = 'retry-wait',
                attempt_count = attempt_count + 1,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = $1::timestamptz,
                last_error = $2,
                updated_at = CURRENT_TIMESTAMP
            WHERE job_key = $3
            "#
        );
        sqlx::query(sql.as_str())
            .bind(next_attempt_at)
            .bind(last_error)
            .bind(job_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn read_active_leased_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
    ) -> Result<Vec<T>, StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            SELECT payload_json
            FROM {table}
            WHERE status IN ('ready', 'leased', 'retry-wait')
            ORDER BY updated_at, job_key
            "#
        );
        let rows = sqlx::query_as::<_, (String,)>(sql.as_str())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn read_ready_leased_jobs<T: DeserializeOwned>(
        &self,
        table: &str,
        now: &str,
    ) -> Result<Vec<T>, StorageError> {
        let table = validated_identifier(table)?;
        let sql = format!(
            r#"
            SELECT payload_json
            FROM {table}
            WHERE
                status = 'ready'
                OR (status = 'retry-wait' AND next_attempt_at <= $1::timestamptz)
                OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= $1::timestamptz)
            ORDER BY next_attempt_at, created_at, job_key
            "#
        );
        let rows = sqlx::query_as::<_, (String,)>(sql.as_str())
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn upsert_json<T: Serialize>(
        &self,
        namespace: &str,
        key: &str,
        value: &T,
    ) -> Result<(), StorageError> {
        let value_json = serde_json::to_string(value)?;
        sqlx::query(
            r#"
            INSERT INTO json_records(namespace, record_key, value_json)
            VALUES ($1, $2, $3)
            ON CONFLICT(namespace, record_key)
            DO UPDATE SET value_json = excluded.value_json, updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(namespace)
        .bind(key)
        .bind(value_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn read_namespace<T: DeserializeOwned>(
        &self,
        namespace: &str,
    ) -> Result<Vec<T>, StorageError> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT value_json FROM json_records WHERE namespace = $1 ORDER BY updated_at, record_key",
        )
        .bind(namespace)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .collect()
    }

    pub async fn read_json<T: DeserializeOwned>(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT value_json FROM json_records WHERE namespace = $1 AND record_key = $2",
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(value_json,)| serde_json::from_str(&value_json).map_err(StorageError::from))
            .transpose()
    }

    pub async fn delete_json(&self, namespace: &str, key: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM json_records WHERE namespace = $1 AND record_key = $2")
            .bind(namespace)
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn count_namespace(&self, namespace: &str) -> Result<i64, StorageError> {
        let (count,) =
            sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM json_records WHERE namespace = $1")
                .bind(namespace)
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }

    pub async fn delete_namespace(&self, namespace: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM json_records WHERE namespace = $1")
            .bind(namespace)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn configured_pool_max_connections(env_key: &str, default: u32) -> u32 {
    env::var(env_key)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

impl DatabaseStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let config = DatabaseConfig::parse(url)?;
        match config.backend() {
            DatabaseBackend::Sqlite => Ok(Self::Sqlite(SqliteJsonStore::connect(url).await?)),
            DatabaseBackend::Postgres => Ok(Self::Postgres(PostgresJsonStore::connect(url).await?)),
        }
    }

    pub fn backend(&self) -> DatabaseBackend {
        match self {
            Self::Sqlite(_) => DatabaseBackend::Sqlite,
            Self::Postgres(_) => DatabaseBackend::Postgres,
        }
    }
}

async fn ensure_json_records_sqlite(pool: &Pool<Sqlite>) -> Result<(), StorageError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS json_records (
            namespace TEXT NOT NULL,
            record_key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(namespace, record_key)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn ensure_json_records_postgres(pool: &Pool<Postgres>) -> Result<(), StorageError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS json_records (
            namespace TEXT NOT NULL,
            record_key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(namespace, record_key)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

fn validated_identifier(value: &str) -> Result<&str, StorageError> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(StorageError::UnsupportedDatabaseUrl);
    }
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonStore {
    root: PathBuf,
}

impl JsonStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn resolve(&self, path: impl AsRef<Path>) -> PathBuf {
        self.root.join(path)
    }

    pub fn read<T: DeserializeOwned>(&self, path: impl AsRef<Path>) -> Result<T, StorageError> {
        let bytes = fs::read(self.resolve(path))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn write<T: Serialize>(
        &self,
        path: impl AsRef<Path>,
        value: &T,
    ) -> Result<(), StorageError> {
        let path = self.resolve(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(value)?;
        fs::write(path, [bytes, b"\n".to_vec()].concat())?;
        Ok(())
    }

    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        self.resolve(path).exists()
    }
}

pub fn did_to_file_name(did: &str) -> String {
    format!("{}.json", did.replace(':', "_"))
}

pub fn storage_safe_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCredentialStore {
    store: JsonStore,
}

impl LocalCredentialStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            store: JsonStore::new(root),
        }
    }

    pub fn root(&self) -> &Path {
        self.store.root()
    }

    pub fn write_node_authorization<T: Serialize>(
        &self,
        credential: &T,
    ) -> Result<(), StorageError> {
        self.write_credential("node-authorization", "root", "self", "latest", credential)?;
        self.store
            .write("credentials/node-authorization.json", credential)
    }

    pub fn read_node_authorization<T: DeserializeOwned>(&self) -> Result<T, StorageError> {
        self.store.read("credentials/node-authorization.json")
    }

    pub fn write_resource_registration<T: Serialize>(
        &self,
        resource_did: &str,
        credential: &T,
    ) -> Result<(), StorageError> {
        self.write_credential(
            "resource-registration",
            "registrar",
            resource_did,
            "latest",
            credential,
        )?;
        self.store.write(
            Path::new("credentials")
                .join("resource-registrations")
                .join(did_to_file_name(resource_did)),
            credential,
        )
    }

    pub fn read_resource_registration<T: DeserializeOwned>(
        &self,
        resource_did: &str,
    ) -> Result<T, StorageError> {
        self.store.read(
            Path::new("credentials")
                .join("resource-registrations")
                .join(did_to_file_name(resource_did)),
        )
    }

    pub fn write_credential<T: Serialize>(
        &self,
        dimension: &str,
        issuer: &str,
        subject: &str,
        credential_id: &str,
        credential: &T,
    ) -> Result<(), StorageError> {
        self.store.write(
            Self::credential_path(dimension, issuer, subject, credential_id),
            credential,
        )
    }

    pub fn read_credential<T: DeserializeOwned>(
        &self,
        dimension: &str,
        issuer: &str,
        subject: &str,
        credential_id: &str,
    ) -> Result<T, StorageError> {
        self.store.read(Self::credential_path(
            dimension,
            issuer,
            subject,
            credential_id,
        ))
    }

    pub fn credential_path(
        dimension: &str,
        issuer: &str,
        subject: &str,
        credential_id: &str,
    ) -> PathBuf {
        Path::new("credentials")
            .join("by-dimension")
            .join(storage_safe_name(dimension))
            .join(storage_safe_name(issuer))
            .join(storage_safe_name(subject))
            .join(format!("{}.json", storage_safe_name(credential_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Example {
        value: String,
    }

    #[test]
    fn round_trips_json() {
        let dir = tempfile::tempdir().unwrap();
        let store = JsonStore::new(dir.path());
        store
            .write(
                "nested/example.json",
                &Example {
                    value: "ok".to_owned(),
                },
            )
            .unwrap();

        let loaded: Example = store.read("nested/example.json").unwrap();
        assert_eq!(loaded.value, "ok");
    }

    #[test]
    fn converts_did_to_file_name() {
        assert_eq!(
            did_to_file_name("did:oan:AGDM:efabc"),
            "did_oan_AGDM_efabc.json"
        );
    }

    #[test]
    fn converts_values_to_storage_safe_names() {
        assert_eq!(
            storage_safe_name("did:oan:AGDM:efabc#credential/1"),
            "did_oan_AGDM_efabc_credential_1"
        );
    }

    #[test]
    fn stores_credentials_under_local_owner_directory() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCredentialStore::new(dir.path());
        let credential = Example {
            value: "local-only".to_owned(),
        };

        store.write_node_authorization(&credential).unwrap();
        store
            .write_resource_registration("did:oan:AGDM:efabc", &credential)
            .unwrap();

        let node_credential: Example = store.read_node_authorization().unwrap();
        let resource_credential: Example = store
            .read_resource_registration("did:oan:AGDM:efabc")
            .unwrap();

        assert_eq!(node_credential, credential);
        assert_eq!(resource_credential, credential);
        assert!(dir
            .path()
            .join("credentials/node-authorization.json")
            .exists());
        assert!(dir
            .path()
            .join("credentials/by-dimension/node-authorization/root/self/latest.json")
            .exists());
    }

    #[test]
    fn stores_multiple_credentials_by_dimension_issuer_and_subject() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCredentialStore::new(dir.path());
        let trust_credential = Example {
            value: "trust".to_owned(),
        };
        let capability_credential = Example {
            value: "capability".to_owned(),
        };

        store
            .write_credential(
                "trust-authorization",
                "did:oan:AGRT:efroot",
                "did:oan:AGDS:efdiscovery",
                "root-auth-v1",
                &trust_credential,
            )
            .unwrap();
        store
            .write_credential(
                "capability-attestation",
                "did:oan:AGRG:efregistrar",
                "did:oan:AGDS:efdiscovery",
                "capability-v1",
                &capability_credential,
            )
            .unwrap();

        let loaded_trust: Example = store
            .read_credential(
                "trust-authorization",
                "did:oan:AGRT:efroot",
                "did:oan:AGDS:efdiscovery",
                "root-auth-v1",
            )
            .unwrap();
        let loaded_capability: Example = store
            .read_credential(
                "capability-attestation",
                "did:oan:AGRG:efregistrar",
                "did:oan:AGDS:efdiscovery",
                "capability-v1",
            )
            .unwrap();

        assert_eq!(loaded_trust, trust_credential);
        assert_eq!(loaded_capability, capability_credential);
    }

    #[test]
    fn parses_database_urls() {
        let sqlite = DatabaseConfig::parse("sqlite:./data/root/root.db").unwrap();
        assert_eq!(sqlite.backend(), DatabaseBackend::Sqlite);
        assert_eq!(sqlite.url(), "sqlite:./data/root/root.db");
        assert_eq!(sqlite.path(), Some(Path::new("./data/root/root.db")));

        let postgres = DatabaseConfig::parse("postgres://localhost/oan").unwrap();
        assert_eq!(postgres.backend(), DatabaseBackend::Postgres);
        assert_eq!(postgres.url(), "postgres://localhost/oan");
        assert_eq!(postgres.path(), None);
    }

    #[tokio::test]
    async fn sqlite_json_store_upserts_and_reads_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite:{}", dir.path().join("store.db").display());
        let store = SqliteJsonStore::connect(&url).await.unwrap();

        store
            .upsert_json(
                "queue",
                "a",
                &Example {
                    value: "first".to_owned(),
                },
            )
            .await
            .unwrap();
        store
            .upsert_json(
                "queue",
                "a",
                &Example {
                    value: "updated".to_owned(),
                },
            )
            .await
            .unwrap();
        store
            .upsert_json(
                "other",
                "b",
                &Example {
                    value: "ignored".to_owned(),
                },
            )
            .await
            .unwrap();

        let rows: Vec<Example> = store.read_namespace("queue").await.unwrap();
        assert_eq!(
            rows,
            vec![Example {
                value: "updated".to_owned()
            }]
        );
        let one: Option<Example> = store.read_json("queue", "a").await.unwrap();
        assert_eq!(one.unwrap().value, "updated");
        assert_eq!(store.count_namespace("queue").await.unwrap(), 1);

        store.delete_json("queue", "a").await.unwrap();
        let rows: Vec<Example> = store.read_namespace("queue").await.unwrap();
        assert!(rows.is_empty());
        store.delete_namespace("other").await.unwrap();
        assert_eq!(store.count_namespace("other").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn leased_job_table_claims_retries_and_lists_active_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite:{}", dir.path().join("leased.db").display());
        let store = SqliteJsonStore::connect(&url).await.unwrap();
        store.ensure_leased_job_table("root_jobs").await.unwrap();
        store
            .enqueue_leased_job(
                "root_jobs",
                "job-1",
                &Example {
                    value: "payload".to_owned(),
                },
                "2026-05-29T00:00:00Z",
            )
            .await
            .unwrap();

        let leased: Vec<LeasedJob<Example>> = store
            .lease_ready_jobs(
                "root_jobs",
                "worker-a",
                10,
                "2026-05-29T00:00:01Z",
                "2026-05-29T00:05:01Z",
            )
            .await
            .unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].job_key, "job-1");
        assert_eq!(leased[0].payload.value, "payload");

        let active: Vec<Example> = store.read_active_leased_jobs("root_jobs").await.unwrap();
        assert_eq!(active.len(), 1);
        let ready: Vec<Example> = store
            .read_ready_leased_jobs("root_jobs", "2026-05-29T00:00:02Z")
            .await
            .unwrap();
        assert!(ready.is_empty());

        store
            .mark_leased_job_retry(
                "root_jobs",
                "job-1",
                "2026-05-29T00:10:01Z",
                Some("network"),
            )
            .await
            .unwrap();
        let ready_before_retry: Vec<Example> = store
            .read_ready_leased_jobs("root_jobs", "2026-05-29T00:09:59Z")
            .await
            .unwrap();
        assert!(ready_before_retry.is_empty());
        let active_before_retry: Vec<Example> =
            store.read_active_leased_jobs("root_jobs").await.unwrap();
        assert_eq!(active_before_retry.len(), 1);
        let ready_after_retry: Vec<Example> = store
            .read_ready_leased_jobs("root_jobs", "2026-05-29T00:10:02Z")
            .await
            .unwrap();
        assert_eq!(ready_after_retry.len(), 1);
        let leased_again: Vec<LeasedJob<Example>> = store
            .lease_ready_jobs(
                "root_jobs",
                "worker-b",
                10,
                "2026-05-29T00:10:02Z",
                "2026-05-29T00:15:02Z",
            )
            .await
            .unwrap();
        assert_eq!(leased_again.len(), 1);
        assert_eq!(leased_again[0].attempt_count, 1);

        store
            .mark_leased_job_succeeded("root_jobs", "job-1")
            .await
            .unwrap();
        let active: Vec<Example> = store.read_active_leased_jobs("root_jobs").await.unwrap();
        assert!(active.is_empty());
    }
}
