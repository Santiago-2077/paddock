"""Paddock — servidor vulnerable LOCAL del lab de ciberseguridad.

ADVERTENCIA: contiene vulnerabilidades INTENCIONALES y DOCUMENTADAS para un
ejercicio académico autorizado (Tecmilenio, Ciberseguridad). Solo uso local,
datos ficticios. NO desplegar. Las vulns se activan con SAFE_MODE=false y se
corrigen con SAFE_MODE=true (contraste del protocolo §4.6).

Arranque:
    SAFE_MODE=false python3 server.py        # versión vulnerable (default)
    SAFE_MODE=true  python3 server.py         # versión corregida
Puerto: 3000 (env PORT para cambiarlo).
"""
import json
import os
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import db
import auth

# Importa el minter local (tools/mint_token.py) para el endpoint de laboratorio.
import importlib.util as _ilu
_mt_path = os.path.join(os.path.dirname(__file__), "tools", "mint_token.py")
_spec = _ilu.spec_from_file_location("mint_token", _mt_path)
mint_token = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(mint_token)

SAFE_MODE = os.environ.get("SAFE_MODE", "false").strip().lower() in ("1", "true", "yes", "on")
PORT = int(os.environ.get("PORT", "3000"))

PLACAS_RE = re.compile(r"^[A-Z]{3}-\d{3}-[A-Z]$")  # regla de negocio (ej. ABC-123-D)


# ----------------------------- helpers HTTP -----------------------------

class Resp(Exception):
    """Respuesta temprana con código + payload (como paddock_json en PHP)."""
    def __init__(self, payload, code=200):
        self.payload = payload
        self.code = code


def categorias_validas(conn):
    return {r["nombre"] for r in conn.execute("SELECT nombre FROM categorias")}


# ----------------------------- endpoints -----------------------------

def ep_vehicles(conn, query):
    rows = conn.execute(
        "SELECT folio, nombre, marca, modelo, anio, placas, categoria, club, resumen, creado_en "
        "FROM vehiculos ORDER BY id DESC LIMIT 500"
    ).fetchall()
    return {"ok": True, "items": [db.row_to_dict(r) for r in rows]}


def ep_search(conn, query):
    """GET /api/vehicles/search?q=&category=

    VULN-SQL-01 (intencional): en modo vulnerable q/category se CONCATENAN en
    el SQL, permitiendo inyección. En SAFE_MODE se usa consulta parametrizada
    con whitelist de columnas (§4.6 corrección).
    """
    q = (query.get("q", [""])[0] or "").strip()
    category = (query.get("category", [""])[0] or "").strip()

    if SAFE_MODE:
        # --- corregido: parametrizado ---
        sql = ("SELECT folio, nombre, marca, modelo, placas, categoria, club "
               "FROM vehiculos WHERE 1=1")
        params = []
        if q:
            sql += (" AND (placas LIKE ? OR nombre LIKE ? OR marca LIKE ? "
                    "OR modelo LIKE ? OR categoria LIKE ?)")
            like = f"%{q}%"
            params += [like, like, like, like, like]
        if category:
            sql += " AND categoria = ?"
            params.append(category)
        sql += " ORDER BY id DESC LIMIT 500"
        rows = conn.execute(sql, params).fetchall()
    else:
        # --- VULN-SQL-01: concatenación directa (NO hacer en producción) ---
        where = []
        if q:
            where.append(
                f"(placas LIKE '%{q}%' OR nombre LIKE '%{q}%' OR marca LIKE '%{q}%' "
                f"OR modelo LIKE '%{q}%' OR categoria LIKE '%{q}%')"
            )
        if category:
            where.append(f"categoria = '{category}'")
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        sql = ("SELECT folio, nombre, marca, modelo, placas, categoria, club "
               f"FROM vehiculos{clause} ORDER BY id DESC LIMIT 500")
        try:
            rows = conn.execute(sql).fetchall()  # executescript NO; single stmt
        except sqlite3.Warning:
            # sqlite rechaza múltiples sentencias en execute(); exponemos el SQL
            raise Resp({"ok": False, "error": "SQL inválido", "sql": sql}, 400)

    return {"ok": True, "safe_mode": SAFE_MODE, "sql_hint": None if SAFE_MODE else sql,
            "count": len(rows), "items": [db.row_to_dict(r) for r in rows]}


def ep_registrations(conn, body):
    """POST /api/registrations

    VULN-VAL-01 (intencional): en modo vulnerable el servicio persiste el
    cuerpo SIN revalidar placas/categoría (la validación 'vivía' solo en la UI).
    En SAFE_MODE revalida el schema en el servidor (§4.6 corrección).
    VULN-LOAD-01: este endpoint no tiene rate-limit (objetivo de carga).
    """
    nombre = str(body.get("ownerName") or body.get("nombre") or "").strip()
    placas = str(body.get("plate") or body.get("placas") or "").strip().upper()
    categoria = str(body.get("category") or body.get("categoria") or "").strip()
    cat_id = body.get("categoryId")
    marca = str(body.get("marca") or "N/D").strip()
    modelo = str(body.get("modelo") or "N/D").strip()
    email = str(body.get("email") or "lab@example.com").strip()
    telefono = str(body.get("telefono") or "0000000000").strip()
    anio = int(body.get("anio") or 2000)
    club = str(body.get("club") or "Independiente").strip()

    # resolver categoría por id si vino categoryId (imita catálogo cerrado)
    if categoria == "" and cat_id is not None:
        row = conn.execute("SELECT nombre FROM categorias WHERE id = ?", (cat_id,)).fetchone()
        categoria = row["nombre"] if row else str(cat_id)

    if SAFE_MODE:
        # --- corregido: validación obligatoria en el servicio ---
        if not nombre or not placas or not categoria:
            raise Resp({"ok": False, "error": "Faltan campos obligatorios."}, 422)
        if not PLACAS_RE.match(placas):
            raise Resp({"ok": False, "error": "Formato de placas inválido (ej. ABC-123-D)."}, 422)
        if categoria not in categorias_validas(conn):
            raise Resp({"ok": False, "error": "Categoría inexistente en el catálogo."}, 422)
    # --- VULN-VAL-01: en modo vulnerable NO se revalida nada aquí ---

    titulo = f"{marca} {modelo} ({categoria})"
    resumen = f"{nombre} · {titulo} · {placas}"
    folio = db.folio("PDK")
    try:
        conn.execute(
            """INSERT INTO vehiculos
               (folio, nombre, email, telefono, marca, modelo, anio, placas,
                categoria, club, concursos, resumen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (folio, nombre, email, telefono, marca, modelo, anio, placas,
             categoria, club, json.dumps([]), resumen),
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        raise Resp({"ok": False, "error": f"Registro duplicado: {e}"}, 409)

    return Resp({"ok": True, "folio": folio, "resumen": resumen,
                 "placas": placas, "categoria": categoria, "safe_mode": SAFE_MODE}, 201)


def ep_passes(conn, query):
    folio = (query.get("folio", [""])[0] or "").strip()
    if not folio:
        raise Resp({"ok": False, "error": "Falta folio."}, 400)
    row = conn.execute(
        "SELECT folio, nombre, marca, modelo, placas, categoria, club, resumen, creado_en "
        "FROM vehiculos WHERE folio = ? LIMIT 1", (folio,)
    ).fetchone()
    if not row:
        raise Resp({"ok": False, "error": "Folio no encontrado."}, 404)
    return {"ok": True, "item": db.row_to_dict(row)}


# -------- rutas admin protegidas (JWT) — NUNCA vulnerables (§4.3) --------

def ep_admin_reports(conn, claims):
    veh = conn.execute("SELECT COUNT(*) FROM vehiculos").fetchone()[0]
    clubs = conn.execute("SELECT COUNT(*) FROM clubs").fetchone()[0]
    por_cat = {r["categoria"]: r["n"] for r in conn.execute(
        "SELECT categoria, COUNT(*) n FROM vehiculos GROUP BY categoria")}
    return {"ok": True, "reporte": {"vehiculos": veh, "clubs": clubs,
            "por_categoria": por_cat}, "by": claims.get("sub", "")[:8]}


def ep_admin_registrations(conn, claims):
    rows = conn.execute(
        "SELECT folio, nombre, email, placas, categoria, club, creado_en "
        "FROM vehiculos ORDER BY id DESC LIMIT 300").fetchall()
    return {"ok": True, "items": [db.row_to_dict(r) for r in rows]}


# ----------------------------- router -----------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "PaddockLab/0.1"

    def _send(self, payload, code=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _require_admin(self):
        hdr = self.headers.get("Authorization", "")
        token = hdr[7:].strip() if hdr.lower().startswith("bearer ") else ""
        ok, claims, err = auth.verify(token, require_group="Admin")
        if not ok:
            # 401 = autenticación falla; 403 = autenticado pero sin permiso
            code = 403 if err == "forbidden" else 401
            raise Resp({"ok": False, "error": err}, code)
        return claims

    def log_message(self, fmt, *args):
        print(f"[paddock] {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")

    def do_OPTIONS(self):
        self._send({"ok": True}, 204)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PATCH(self):
        self._route("PATCH")

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _route(self, method):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        query = parse_qs(u.query)
        conn = db.get_conn()
        try:
            if method == "GET" and path == "/api/vehicles":
                self._ok(ep_vehicles(conn, query)); return
            if method == "GET" and path == "/api/vehicles/search":
                self._ok(ep_search(conn, query)); return
            if method == "GET" and path == "/api/passes":
                self._ok(ep_passes(conn, query)); return
            if method == "POST" and path == "/api/registrations":
                self._ok(ep_registrations(conn, self._read_body())); return
            if method == "GET" and path == "/api/admin/reports":
                self._ok(ep_admin_reports(conn, self._require_admin())); return
            if method == "GET" and path == "/api/admin/registrations":
                self._ok(ep_admin_registrations(conn, self._require_admin())); return
            if method == "GET" and path == "/api/_lab/token":
                # LAB ONLY: sustituye la emisión de token de Cognito en el entorno
                # local. kind = admin|participante|expired|tampered.
                kind = (query.get("kind", ["admin"])[0] or "admin").strip()
                if kind not in ("admin", "participante", "expired", "tampered"):
                    raise Resp({"ok": False, "error": "kind inválido."}, 400)
                self._send({"ok": True, "kind": kind, "token": mint_token.mint(kind)}); return
            if path == "/" or path == "/health":
                self._send({"ok": True, "service": "paddock-lab", "safe_mode": SAFE_MODE}); return
            raise Resp({"ok": False, "error": "Ruta no encontrada."}, 404)
        except Resp as r:
            self._send(r.payload, r.code)
        except Exception as e:  # noqa
            self._send({"ok": False, "error": str(e)}, 500)

    def _ok(self, result):
        if isinstance(result, Resp):
            self._send(result.payload, result.code)
        else:
            self._send(result, 200)


def main():
    db.init_db()
    mode = "SAFE (corregido)" if SAFE_MODE else "VULNERABLE (intencional)"
    print(f"[paddock] escuchando en http://127.0.0.1:{PORT}  | modo: {mode}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
