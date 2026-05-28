import os
import sqlite3
import hashlib
from flask import g
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'queue.db')


def hash_password(password):
    return generate_password_hash(password)


def check_password(stored_hash, password):
    if stored_hash and (stored_hash.startswith('pbkdf2:') or stored_hash.startswith('scrypt:')):
        return check_password_hash(stored_hash, password)
    if stored_hash == hashlib.sha256(password.encode()).hexdigest():
        return True
    return False


def upgrade_password_hash(db, user_id, current_hash, password):
    if current_hash and (current_hash.startswith('pbkdf2:') or current_hash.startswith('scrypt:')):
        return
    new_hash = generate_password_hash(password)
    db.execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, user_id))
    db.commit()


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")

    db.executescript('''
        CREATE TABLE IF NOT EXISTS shops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT 'Main Barbershop',
            is_open INTEGER NOT NULL DEFAULT 1,
            is_paused INTEGER NOT NULL DEFAULT 0,
            pause_reason TEXT,
            avg_haircut_minutes INTEGER NOT NULL DEFAULT 20,
            next_number INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER NOT NULL,
            customer_name TEXT NOT NULL,
            queue_number INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'waiting',
            position INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id)
        );
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER NOT NULL DEFAULT 1,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'assistant',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id)
        );
        CREATE TABLE IF NOT EXISTS barbers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER NOT NULL DEFAULT 1,
            user_id INTEGER NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'available',
            current_customer_id INTEGER,
            active INTEGER NOT NULL DEFAULT 1,
            on_shift INTEGER NOT NULL DEFAULT 0,
            auto_assign INTEGER NOT NULL DEFAULT 1,
            last_seen TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS system_control (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            is_stopped INTEGER NOT NULL DEFAULT 0,
            password_hash TEXT,
            is_initialized INTEGER NOT NULL DEFAULT 0
        );
    ''')

    for col in ['next_number', 'instagram', 'facebook', 'youtube', 'whatsapp', 'phone', 'location', 'working_hours', 'hero_title', 'hero_desc']:
        try:
            db.execute(f"ALTER TABLE shops ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass

    for col_def in [
        ('assigned_barber_id', 'INTEGER'),
        ('started_at', 'TIMESTAMP'),
        ('completed_at', 'TIMESTAMP'),
        ('duration_minutes', 'INTEGER'),
    ]:
        try:
            db.execute(f"ALTER TABLE queue ADD COLUMN {col_def[0]} {col_def[1]}")
        except sqlite3.OperationalError:
            pass

    try:
        db.execute("ALTER TABLE queue ADD COLUMN leave_token TEXT")
    except sqlite3.OperationalError:
        pass

    try:
        db.execute("ALTER TABLE queue ADD COLUMN selected_barber INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    for col_def in [
        ('on_shift', 'INTEGER DEFAULT 0'),
        ('auto_assign', 'INTEGER DEFAULT 1'),
    ]:
        try:
            db.execute(f"ALTER TABLE barbers ADD COLUMN {col_def[0]} {col_def[1]}")
        except sqlite3.OperationalError:
            pass

    db.execute("UPDATE barbers SET on_shift = 1 WHERE on_shift IS NULL")
    db.execute("UPDATE barbers SET auto_assign = 1 WHERE auto_assign IS NULL")

    cur = db.execute("SELECT COUNT(*) FROM shops")
    if cur.fetchone()[0] == 0:
        db.execute(
            "INSERT INTO shops (name, instagram, facebook, youtube, whatsapp, phone, location, working_hours, hero_title, hero_desc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ('Main Barbershop', '', '', '', '', '', '', 'Mon-Fri 9:00-20:00 | Sat 10:00-18:00', 'The Art of\nthe Cut', 'Where precision meets style.')
        )

    admin_count = db.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    if user_count == 0:
        if admin_count > 0:
            admins = db.execute("SELECT * FROM admins").fetchall()
            for a in admins:
                db.execute(
                    "INSERT INTO users (id, shop_id, username, password, role, active) VALUES (?, ?, ?, ?, 'owner', 1)",
                    (a['id'], 1, a['username'], a['password'])
                )
        else:
            hashed_pw = hash_password('admin123')
            db.execute("INSERT INTO admins (username, password) VALUES (?, ?)",
                       ('admin', hashed_pw))
            db.execute("INSERT INTO users (shop_id, username, password, role, active) VALUES (?, ?, ?, 'owner', 1)",
                       (1, 'admin', hashed_pw))

    barber_count = db.execute("SELECT COUNT(*) FROM barbers").fetchone()[0]
    if barber_count == 0:
        owner = db.execute("SELECT * FROM users WHERE role = 'owner' LIMIT 1").fetchone()
        if owner:
            display_name = owner['username'].capitalize()
            db.execute(
                "INSERT INTO barbers (shop_id, user_id, display_name, status, active) VALUES (?, ?, ?, 'available', 1)",
                (1, owner['id'], display_name)
            )

    db.execute("UPDATE barbers SET current_customer_id = NULL")

    scp_count = db.execute("SELECT COUNT(*) FROM system_control").fetchone()[0]
    if scp_count == 0:
        db.execute("INSERT INTO system_control (is_stopped, is_initialized) VALUES (0, 0)")

    db.commit()
    db.close()
