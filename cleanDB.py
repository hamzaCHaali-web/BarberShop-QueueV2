import os
import sqlite3
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'queue.db')


def clean_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
        print("Deleted existing queue.db")

    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=OFF")
    db.execute("PRAGMA journal_mode=WAL")

    db.executescript('''
        CREATE TABLE shops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT 'Main Barbershop',
            is_open INTEGER NOT NULL DEFAULT 1,
            is_paused INTEGER NOT NULL DEFAULT 0,
            pause_reason TEXT,
            avg_haircut_minutes INTEGER NOT NULL DEFAULT 20,
            next_number INTEGER NOT NULL DEFAULT 1,
            instagram TEXT,
            facebook TEXT,
            youtube TEXT,
            whatsapp TEXT,
            phone TEXT,
            location TEXT,
            working_hours TEXT,
            hero_title TEXT,
            hero_desc TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER NOT NULL,
            customer_name TEXT NOT NULL,
            queue_number INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'waiting',
            position INTEGER NOT NULL,
            assigned_barber_id INTEGER,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            duration_minutes INTEGER,
            leave_token TEXT,
            selected_barber INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id)
        );

        CREATE TABLE admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER NOT NULL DEFAULT 1,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'assistant',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id)
        );

        CREATE TABLE barbers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_id INTEGER NOT NULL DEFAULT 1,
            user_id INTEGER NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'available',
            current_customer_id INTEGER,
            active INTEGER NOT NULL DEFAULT 1,
            on_shift INTEGER NOT NULL DEFAULT 1,
            auto_assign INTEGER NOT NULL DEFAULT 1,
            last_seen TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES shops(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE system_control (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            is_stopped INTEGER NOT NULL DEFAULT 0,
            password_hash TEXT,
            is_initialized INTEGER NOT NULL DEFAULT 0
        );
    ''')

    db.execute(
        "INSERT INTO shops (name, instagram, facebook, youtube, whatsapp, phone, location, working_hours, hero_title, hero_desc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ('Main Barbershop', '', '', '', '', '', '', 'Mon-Fri 9:00-20:00 | Sat 10:00-18:00', 'The Art of\nthe Cut', 'Where precision meets style.')
    )

    hashed_pw = generate_password_hash('admin123')
    db.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ('admin', hashed_pw))
    db.execute("INSERT INTO users (shop_id, username, password, role, active) VALUES (?, ?, ?, 'owner', 1)", (1, 'admin', hashed_pw))

    owner = db.execute("SELECT * FROM users WHERE role = 'owner' LIMIT 1").fetchone()
    if owner:
        db.execute(
            "INSERT INTO barbers (shop_id, user_id, display_name, status, active) VALUES (?, ?, ?, 'available', 1)",
            (1, owner['id'], 'Admin')
        )

    db.execute("INSERT INTO system_control (is_stopped, is_initialized) VALUES (0, 0)")

    db.commit()
    db.close()
    print("Database cleaned and re-initialized successfully")
    print("Admin account: admin / admin123")


if __name__ == '__main__':
    clean_db()
