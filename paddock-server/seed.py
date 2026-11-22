"""Seed de datos ficticios del protocolo (§4.5).
Idempotente: reinicia las tablas y vuelve a insertar. NUNCA datos reales.
"""
import json
import db


CATEGORIAS = ["Classic", "Modified", "JDM", "Muscle", "Euro"]

VEHICULOS = [
    # nombre, email, tel, marca, modelo, anio, placas, categoria, club
    ("Pedro Participante", "pedro@example.com", "5550000001",
     "Nissan", "Skyline R34", 1999, "ABC-123-D", "Classic", "CDMX Retro"),
    ("Pedro Participante", "pedro@example.com", "5550000001",
     "Honda", "Civic EK9", 1998, "XYZ-987-A", "Modified", "Independiente"),
    ("Jane Admin", "jane.admin@example.com", "5550000002",
     "Toyota", "Supra MK4", 1994, "SUP-444-B", "JDM", "CDMX Retro"),
]

CLUBS = [
    # nombre_club, zona, estilo, contacto, email, tel, redes, autos, stands, desc
    ("CDMX Retro", "Sur CDMX", "Classic", "Jane Admin",
     "jane.admin@example.com", "5550000002", "@cdmxretro", 12, 1,
     "Club de autos clásicos de la Ciudad de México."),
]


def run() -> None:
    db.init_db()
    conn = db.get_conn()
    conn.executescript("DELETE FROM vehiculos; DELETE FROM clubs; DELETE FROM categorias;")

    for i, nombre in enumerate(CATEGORIAS, start=1):
        conn.execute("INSERT INTO categorias (id, nombre) VALUES (?, ?)", (i, nombre))

    for (nombre, email, tel, marca, modelo, anio, placas, cat, club) in VEHICULOS:
        titulo = f"{marca} {modelo} ({cat})"
        resumen = f"{nombre} · {titulo} · {placas}"
        conn.execute(
            """INSERT INTO vehiculos
               (folio, nombre, email, telefono, marca, modelo, anio, placas,
                categoria, club, concursos, resumen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (db.folio("PDK"), nombre, email, tel, marca, modelo, anio, placas,
             cat, club, json.dumps([]), resumen),
        )

    for (nc, zona, estilo, contacto, email, tel, redes, autos, stands, desc) in CLUBS:
        resumen = f"{contacto} · {autos} autos · {zona}"
        conn.execute(
            """INSERT INTO clubs
               (folio, nombre_club, zona, estilo, contacto, email, telefono,
                redes, autos, stands, descripcion, resumen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (db.folio("CLUB"), nc, zona, estilo, contacto, email, tel,
             redes, autos, stands, desc, resumen),
        )

    conn.commit()
    v = conn.execute("SELECT COUNT(*) FROM vehiculos").fetchone()[0]
    c = conn.execute("SELECT COUNT(*) FROM clubs").fetchone()[0]
    print(f"[seed] {v} vehiculos, {c} clubs, {len(CATEGORIAS)} categorias -> {db.DB_PATH}")


if __name__ == "__main__":
    run()
