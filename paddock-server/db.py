"""Paddock lab — capa de datos SQLite (stdlib).

Modelo adaptado de cars/paddock_cdmx.sql (MySQL -> SQLite):
  JSON      -> TEXT (json serializado)
  TIMESTAMP -> TEXT (ISO 8601)
Nada aquí es vulnerable; las vulnerabilidades viven en server.py y están
gobernadas por SAFE_MODE. Este módulo solo expone helpers parametrizados
y una conexión por hilo.
"""
import os
import sqlite3
import secrets
import time
import threading

DB_PATH = os.environ.get(
    "PADDOCK_DB",
    os.path.join(os.path.dirname(__file__), "paddock.db"),
)

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS vehiculos (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  folio     TEXT NOT NULL UNIQUE,
  nombre    TEXT NOT NULL,
  email     TEXT NOT NULL,
  telefono  TEXT NOT NULL,
  marca     TEXT NOT NULL,
  modelo    TEXT NOT NULL,
  anio      INTEGER NOT NULL,
  placas    TEXT NOT NULL UNIQUE,
  categoria TEXT NOT NULL,
  club      TEXT NOT NULL DEFAULT 'Independiente',
  concursos TEXT,
  resumen   TEXT NOT NULL,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_categoria ON vehiculos(categoria);
CREATE INDEX IF NOT EXISTS idx_club      ON vehiculos(club);
CREATE INDEX IF NOT EXISTS idx_email     ON vehiculos(email);

CREATE TABLE IF NOT EXISTS clubs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  folio       TEXT NOT NULL UNIQUE,
  nombre_club TEXT NOT NULL UNIQUE,
  zona        TEXT NOT NULL,
  estilo      TEXT NOT NULL,
  contacto    TEXT NOT NULL,
  email       TEXT NOT NULL,
  telefono    TEXT NOT NULL,
  redes       TEXT,
  autos       INTEGER NOT NULL,
  stands      INTEGER NOT NULL DEFAULT 0,
  descripcion TEXT NOT NULL,
  resumen     TEXT NOT NULL,
  creado_en   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_estilo ON clubs(estilo);
CREATE INDEX IF NOT EXISTS idx_zona   ON clubs(zona);

-- Catálogo cerrado de categorías (protocolo §4.5: rechazo si no existe)
CREATE TABLE IF NOT EXISTS categorias (
  id     INTEGER PRIMARY KEY,
  nombre TEXT NOT NULL UNIQUE
);
"""

# Columnas permitidas para búsqueda en modo seguro (whitelist, §4.6)
SEARCH_COLUMNS = {"placas", "nombre", "marca", "modelo", "categoria", "club"}


def get_conn() -> sqlite3.Connection:
    """Conexión por hilo (ThreadingHTTPServer usa varios)."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        _local.conn = conn
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()


def folio(prefix: str) -> str:
    """Portado de paddock_folio() en cars/site/bat/db.php."""
    rand = secrets.token_hex(3).upper()
    t = _base36(int(time.time()))
    return f"{prefix}-{t}-{rand}"


def _base36(n: int) -> str:
    if n == 0:
        return "0"
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = digits[r] + out
    return out


def row_to_dict(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in row.keys()}
