import os
import sqlite3
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g, session, send_from_directory
from database import get_db, close_db, init_db, check_password, hash_password
from routes.admin import admin_bp
from routes.scp import scp_bp
from utils import sanitize_input

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def validate_string(value, field_name, min_len=1, max_len=None):
    if not isinstance(value, str):
        return f'{field_name} must be text'
    stripped = value.strip()
    if len(stripped) < min_len:
        return f'{field_name} must be at least {min_len} character{"s" if min_len > 1 else ""}'
    if max_len and len(stripped) > max_len:
        return f'{field_name} must not exceed {max_len} characters'
    return None


def validate_int(value, field_name, min_val=None, max_val=None):
    if not isinstance(value, int) or isinstance(value, bool):
        return f'{field_name} must be a number'
    if min_val is not None and value < min_val:
        return f'{field_name} must be at least {min_val}'
    if max_val is not None and value > max_val:
        return f'{field_name} must not exceed {max_val}'
    return None


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_id = session.get('admin_id')
        if not admin_id:
            return jsonify({'error': 'Authentication required'}), 401
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (admin_id,)).fetchone()
        if not user:
            session.clear()
            return jsonify({'error': 'Authentication required'}), 401
        g.admin = user
        g.shop_id = user['shop_id'] if user['shop_id'] is not None else 1
        if request.method in ('POST', 'PUT', 'DELETE'):
            _csrf = session.get('csrf_token')
            header_token = request.headers.get('X-CSRF-Token', '')
            if _csrf and header_token != _csrf:
                logger.warning(f"CSRF validation failed for {request.path}")
                return jsonify({'error': 'Invalid CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated


def require_owner(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_id = session.get('admin_id')
        if not admin_id:
            return jsonify({'error': 'Authentication required'}), 401
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (admin_id,)).fetchone()
        if not user:
            session.clear()
            return jsonify({'error': 'Authentication required'}), 401
        if user['role'] != 'owner':
            return jsonify({'error': 'Owner privileges required'}), 403
        g.admin = user
        g.shop_id = user['shop_id'] if user['shop_id'] is not None else 1
        if request.method in ('POST', 'PUT', 'DELETE'):
            _csrf = session.get('csrf_token')
            header_token = request.headers.get('X-CSRF-Token', '')
            if _csrf and header_token != _csrf:
                logger.warning(f"CSRF validation failed for {request.path}")
                return jsonify({'error': 'Invalid CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated


def require_barber(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_id = session.get('admin_id')
        if not admin_id:
            return jsonify({'error': 'Authentication required'}), 401
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (admin_id,)).fetchone()
        if not user:
            session.clear()
            return jsonify({'error': 'Authentication required'}), 401
        g.admin = user
        g.shop_id = user['shop_id'] if user['shop_id'] is not None else 1
        barber = db.execute(
            "SELECT * FROM barbers WHERE user_id = ? AND shop_id = ? AND active = 1 AND on_shift = 1",
            (user['id'], g.shop_id)
        ).fetchone()
        if not barber:
            return jsonify({'error': 'Barber not found or not on shift'}), 403
        g.barber = barber
        if request.method in ('POST', 'PUT', 'DELETE'):
            _csrf = session.get('csrf_token')
            header_token = request.headers.get('X-CSRF-Token', '')
            if _csrf and header_token != _csrf:
                logger.warning(f"CSRF validation failed for {request.path}")
                return jsonify({'error': 'Invalid CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_DIR = os.path.join(BASE_DIR, 'client')

app = Flask(__name__)

app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True,  # Set to True in production with HTTPS
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

DEV_FRONTENDS = {'http://localhost:5173', 'http://127.0.0.1:5173'}
PROD_FRONTEND = os.environ.get('FRONTEND_URL', '').rstrip('/')
TRUSTED_ORIGINS = DEV_FRONTENDS | ({PROD_FRONTEND} if PROD_FRONTEND else set())

app.teardown_appcontext(close_db)
app.register_blueprint(admin_bp)
app.register_blueprint(scp_bp)


@app.after_request
def add_cors_and_security_headers(response):
    origin = request.headers.get('Origin')
    if origin in TRUSTED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-CSRF-Token'
    response.headers['Access-Control-Max-Age'] = '3600'
    response.headers['Access-Control-Expose-Headers'] = 'X-CSRF-Token'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self' http://localhost:5173 ws://localhost:* https://unpkg.com; "
        "frame-ancestors 'none';"
    )
    return response


def recalc_positions(shop_id):
    db = get_db()
    rows = db.execute(
        "SELECT id FROM queue WHERE shop_id = ? AND status IN ('waiting', 'current') ORDER BY position",
        (shop_id,)
    ).fetchall()
    for idx, row in enumerate(rows):
        db.execute("UPDATE queue SET position = ? WHERE id = ?", (idx + 1, row['id']))
    db.commit()


def take_next(barber_id, shop_id):
    db = get_db()
    barber = db.execute(
        "SELECT * FROM barbers WHERE id = ? AND shop_id = ? AND active = 1 AND on_shift = 1",
        (barber_id, shop_id)
    ).fetchone()
    if not barber:
        return None, 'Barber not found or not on shift'

    existing = db.execute(
        "SELECT id FROM queue WHERE shop_id = ? AND assigned_barber_id = ? AND status = 'current'",
        (shop_id, barber_id)
    ).fetchone()
    if existing:
        return None, 'Barber already has a current customer'

    now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    cur = db.execute(
        """UPDATE queue SET status = 'current', assigned_barber_id = ?, started_at = ?
           WHERE id = (
               SELECT id FROM queue
               WHERE shop_id = ? AND status = 'waiting'
               ORDER BY position LIMIT 1
           ) AND status = 'waiting'""",
        (barber_id, now_str, shop_id)
    )

    if cur.rowcount == 0:
        return None, 'No waiting customers'

    customer = db.execute(
        "SELECT * FROM queue WHERE shop_id = ? AND assigned_barber_id = ? AND status = 'current'",
        (shop_id, barber_id)
    ).fetchone()
    if not customer:
        logger.error(f"Failed to retrieve claimed customer for barber {barber_id} in shop {shop_id}")
        return None, 'Operation failed'

    db.execute("UPDATE barbers SET status = 'busy' WHERE id = ?", (barber_id,))
    db.commit()

    return customer, None


def finish_current(barber_id, shop_id):
    db = get_db()
    barber = db.execute(
        "SELECT * FROM barbers WHERE id = ? AND shop_id = ? AND active = 1",
        (barber_id, shop_id)
    ).fetchone()
    if not barber:
        return None, 'Barber not found'

    customer = db.execute(
        "SELECT * FROM queue WHERE shop_id = ? AND assigned_barber_id = ? AND status = 'current'",
        (shop_id, barber_id)
    ).fetchone()
    if not customer:
        return None, 'No current customer assigned to this barber'

    now = datetime.utcnow()
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')

    duration = None
    if customer['started_at']:
        started_dt = datetime.strptime(customer['started_at'], '%Y-%m-%d %H:%M:%S')
        duration = max(1, int((now - started_dt).total_seconds() / 60))

    db.execute(
        "UPDATE queue SET status = 'completed', completed_at = ?, duration_minutes = ? WHERE id = ?",
        (now_str, duration, customer['id'])
    )
    db.execute(
        "UPDATE barbers SET status = 'available' WHERE id = ?",
        (barber_id,)
    )
    db.commit()

    updated = db.execute("SELECT * FROM queue WHERE id = ?", (customer['id'],)).fetchone()
    return updated, None


def auto_take_next(shop_id):
    db = get_db()
    busy_ids = set(
        r['assigned_barber_id'] for r in db.execute(
            "SELECT DISTINCT assigned_barber_id FROM queue WHERE shop_id = ? AND status = 'current' AND assigned_barber_id IS NOT NULL",
            (shop_id,)
        ).fetchall()
    )
    barbers = db.execute(
        "SELECT * FROM barbers WHERE shop_id = ? AND active = 1 AND on_shift = 1 AND status = 'available' ORDER BY id",
        (shop_id,)
    ).fetchall()
    for barber in barbers:
        if barber['id'] in busy_ids:
            continue
        entry, err = take_next(barber['id'], shop_id)
        if entry:
            return entry
    return None


@app.route('/api/join', methods=['POST'])
def join_queue():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400
    name = data.get('customer_name', '').strip()
    shop_id = data.get('shop_id', 1)

    err = validate_string(name, 'customer_name', max_len=50)
    if err:
        return jsonify({'error': err}), 400

    name = sanitize_input(name, max_length=50)

    db = get_db()
    shop = db.execute("SELECT * FROM shops WHERE id = ?", (shop_id,)).fetchone()
    if not shop:
        return jsonify({'error': 'Shop not found'}), 404
    if not shop['is_open']:
        return jsonify({'error': 'Shop is closed'}), 400

    new_number = shop['next_number']
    db.execute("UPDATE shops SET next_number = next_number + 1 WHERE id = ?", (shop_id,))

    row = db.execute(
        "SELECT COALESCE(MAX(position), 0) as max_pos FROM queue WHERE shop_id = ? AND status IN ('waiting', 'current')",
        (shop_id,)
    ).fetchone()
    new_pos = row['max_pos'] + 1

    leave_token = secrets.token_urlsafe(16)

    cur = db.execute(
        "INSERT INTO queue (shop_id, customer_name, queue_number, position, status, leave_token) VALUES (?, ?, ?, ?, 'waiting', ?)",
        (shop_id, name, new_number, new_pos, leave_token)
    )
    db.commit()
    recalc_positions(shop_id)
    auto_take_next(shop_id)

    entry = db.execute("SELECT * FROM queue WHERE id = ?", (cur.lastrowid,)).fetchone()

    return jsonify({
        'id': entry['id'],
        'queue_number': entry['queue_number'],
        'position': entry['position'],
        'customer_name': entry['customer_name'],
        'status': entry['status'],
        'leave_token': entry['leave_token']
    }), 201


@app.route('/api/queue', methods=['GET'])
def get_queue():
    shop_id = request.args.get('shop_id', 1, type=int)
    customer_id = request.args.get('customer_id', None, type=int)

    db = get_db()
    shop = db.execute("SELECT * FROM shops WHERE id = ?", (shop_id,)).fetchone()
    if not shop:
        return jsonify({'error': 'Shop not found'}), 404

    active = db.execute(
        "SELECT * FROM queue WHERE shop_id = ? AND status IN ('waiting', 'current') ORDER BY position",
        (shop_id,)
    ).fetchall()

    barbers = db.execute(
        "SELECT * FROM barbers WHERE shop_id = ? AND active = 1",
        (shop_id,)
    ).fetchall()

    barber_map = {b['id']: b for b in barbers}

    now = datetime.utcnow()

    current_queue_entries = [
        e for e in active
        if e['status'] == 'current' and e['assigned_barber_id'] is not None
    ]
    barber_current_map = {e['assigned_barber_id']: e['id'] for e in current_queue_entries}

    current_entry = None
    current_entries = []
    for b in barbers:
        cid = barber_current_map.get(b['id'])
        if cid is not None:
            c = next((e for e in current_queue_entries if e['id'] == cid), None)
            if c:
                barber_entry = {
                    'id': c['id'],
                    'queue_number': c['queue_number'],
                    'customer_name': c['customer_name'],
                    'position': c['position'],
                    'status': 'current',
                    'estimated_wait_minutes': None,
                    'created_at': c['created_at'],
                    'started_at': c['started_at'],
                    'barber_id': b['id'],
                    'barber_name': b['display_name']
                }
                current_entries.append(barber_entry)
                if current_entry is None:
                    current_entry = barber_entry

    active_barber_count = max(
        len([b for b in barbers if b['on_shift'] and (b['status'] == 'available' or b['id'] in barber_current_map)]),
        1
    )
    avg_min = shop['avg_haircut_minutes']

    queue_list = []
    for e in active:
        entry = {
            'id': e['id'],
            'queue_number': e['queue_number'],
            'customer_name': e['customer_name'],
            'position': e['position'],
            'status': 'waiting',
            'estimated_wait_minutes': None,
            'created_at': e['created_at']
        }
        if e['assigned_barber_id'] is not None and e['status'] == 'current':
            entry['status'] = 'current'
            assigned_b = barber_map.get(e['assigned_barber_id'])
            if assigned_b:
                entry['barber_id'] = assigned_b['id']
                entry['barber_name'] = assigned_b['display_name']
            if e['started_at']:
                started = datetime.strptime(e['started_at'], '%Y-%m-%d %H:%M:%S')
                elapsed = (now - started).total_seconds() / 60
            else:
                elapsed = 0
            w = max(0, avg_min - elapsed if elapsed < avg_min else 2)
            entry['estimated_wait_minutes'] = round(w, 1)
        queue_list.append(entry)

    for entry in queue_list:
        if entry['status'] == 'waiting' and entry['estimated_wait_minutes'] is None:
            ahead = sum(1 for q in queue_list if q['status'] == 'waiting' and q['position'] < entry['position'])
            cur_count = len(current_entries)
            est_wait = (ahead + cur_count) * avg_min / active_barber_count
            entry['estimated_wait_minutes'] = round(est_wait, 1)

    customer_data = None
    if customer_id:
        entry = db.execute(
            "SELECT * FROM queue WHERE id = ? AND shop_id = ?",
            (customer_id, shop_id)
        ).fetchone()
        if entry:
            display_status = entry['status']
            if (
                entry['status'] == 'current'
                and (
                    entry['assigned_barber_id'] is None
                    or entry['assigned_barber_id'] not in barber_current_map
                )
            ):
                display_status = 'waiting'
            customer_data = {
                'id': entry['id'],
                'queue_number': entry['queue_number'],
                'customer_name': entry['customer_name'],
                'position': entry['position'],
                'status': display_status,
                'estimated_wait_minutes': None,
                'leave_token': entry['leave_token']
            }
            if display_status in ('waiting', 'current'):
                match = next((q for q in queue_list if q['id'] == entry['id']), None)
                if match and match['estimated_wait_minutes'] is not None:
                    customer_data['estimated_wait_minutes'] = match['estimated_wait_minutes']

    today_q = db.execute(
        "SELECT status, COUNT(*) as cnt FROM queue WHERE shop_id = ? AND DATE(created_at) = DATE('now') GROUP BY status",
        (shop_id,)
    ).fetchall()
    today_stats = {r['status']: r['cnt'] for r in today_q}

    return jsonify({
        'shop': {
            'id': shop['id'],
            'name': shop['name'],
            'is_open': bool(shop['is_open']),
            'is_paused': bool(shop['is_paused']),
            'pause_reason': shop['pause_reason'],
            'avg_haircut_minutes': shop['avg_haircut_minutes'],
            'instagram': shop['instagram'],
            'facebook': shop['facebook'],
            'youtube': shop['youtube'],
            'whatsapp': shop['whatsapp'],
            'phone': shop['phone'],
            'location': shop['location'],
            'working_hours': shop['working_hours'],
            'hero_title': shop['hero_title'],
            'hero_desc': shop['hero_desc']
        },
        'queue': queue_list,
        'current_customer': current_entry,
        'current_customers': current_entries,
        'barbers': [{
            'id': b['id'],
            'display_name': b['display_name'],
            'status': b['status'],
            'on_shift': bool(b['on_shift']),
            'user_id': b['user_id']
        } for b in barbers],
        'waiting_count': len([e for e in queue_list if e['status'] == 'waiting']),
        'active_barber_count': active_barber_count,
        'stats': {
            'completed_today': today_stats.get('completed', 0),
            'skipped_today': today_stats.get('skipped', 0),
            'total_served_today': today_stats.get('completed', 0) + today_stats.get('skipped', 0),
            'currently_waiting': len([e for e in queue_list if e['status'] == 'waiting']),
            'avg_wait_time': shop['avg_haircut_minutes']
        },
        'customer': customer_data
    })


@app.route('/api/finish', methods=['POST'])
@require_barber
def finish_customer():
    barber = g.barber
    completed, err = finish_current(barber['id'], g.shop_id)
    if err:
        return jsonify({'error': err}), 400

    recalc_positions(g.shop_id)
    take_next(barber['id'], g.shop_id)

    return jsonify({'message': 'Customer finished', 'customer': completed['customer_name']})


@app.route('/api/skip', methods=['POST'])
@require_admin
def skip_customer():
    data = request.get_json() or {}
    entry_id = data.get('entry_id', None)

    db = get_db()

    if not entry_id:
        barber = db.execute(
            "SELECT * FROM barbers WHERE user_id = ? AND shop_id = ? AND active = 1 AND on_shift = 1",
            (g.admin['id'], g.shop_id)
        ).fetchone()
        if not barber:
            return jsonify({'error': 'Barber not found or not on shift'}), 400
        entry = db.execute(
            "SELECT * FROM queue WHERE shop_id = ? AND assigned_barber_id = ? AND status = 'current'",
            (g.shop_id, barber['id'])
        ).fetchone()
        if not entry:
            return jsonify({'error': 'No current customer to skip'}), 400
        entry_id = entry['id']

    entry = db.execute("SELECT * FROM queue WHERE id = ? AND shop_id = ?", (entry_id, g.shop_id)).fetchone()
    if not entry:
        return jsonify({'error': 'Entry not found'}), 404
    if entry['status'] not in ('waiting', 'current'):
        return jsonify({'error': 'Cannot skip this entry'}), 400

    now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    if entry['status'] == 'current':
        db.execute(
            "UPDATE queue SET status = 'skipped', completed_at = ? WHERE id = ?",
            (now_str, entry_id)
        )
        db.execute(
            "UPDATE barbers SET status = 'available' WHERE id = ?",
            (entry['assigned_barber_id'],)
        )
    else:
        db.execute("UPDATE queue SET status = 'skipped' WHERE id = ?", (entry_id,))

    db.commit()
    recalc_positions(g.shop_id)

    if entry['status'] == 'current':
        auto_take_next(g.shop_id)

    return jsonify({'message': 'Customer skipped'})


@app.route('/api/leave', methods=['POST'])
def leave_queue():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400
    entry_id = data.get('entry_id')
    shop_id = data.get('shop_id', 1)
    leave_token = data.get('leave_token')

    if not entry_id:
        return jsonify({'error': 'Entry ID is required'}), 400
    if not isinstance(entry_id, int) or entry_id < 1:
        return jsonify({'error': 'Invalid entry ID'}), 400

    db = get_db()
    entry = db.execute("SELECT * FROM queue WHERE id = ? AND shop_id = ?", (entry_id, shop_id)).fetchone()
    if not entry:
        return jsonify({'error': 'Entry not found'}), 404
    if entry['status'] == 'left':
        return jsonify({'error': 'Already left'}), 400

    if entry['leave_token']:
        if not leave_token:
            return jsonify({'error': 'Leave token is required to leave the queue'}), 400
        if leave_token != entry['leave_token']:
            return jsonify({'error': 'Invalid leave token'}), 403

    was_current = entry['status'] == 'current'

    db.execute("UPDATE queue SET status = 'left' WHERE id = ?", (entry_id,))
    db.commit()

    if was_current and entry['assigned_barber_id'] is not None:
        db.execute(
            "UPDATE barbers SET status = 'available' WHERE id = ?",
            (entry['assigned_barber_id'],)
        )
        db.commit()

    recalc_positions(shop_id)
    auto_take_next(shop_id)

    return jsonify({'message': 'Successfully left the queue'})


@app.route('/api/reset', methods=['POST'])
@require_admin
def reset_queue():
    logger.info(f"Queue reset by user {g.admin['id']} for shop {g.shop_id}")

    db = get_db()
    db.execute(
        "UPDATE queue SET status = 'left' WHERE shop_id = ? AND status IN ('waiting', 'current')",
        (g.shop_id,)
    )
    db.execute(
        "UPDATE barbers SET status = 'available' WHERE shop_id = ?",
        (g.shop_id,)
    )
    db.execute("UPDATE shops SET is_paused = 0, pause_reason = NULL, next_number = 1 WHERE id = ?", (g.shop_id,))
    db.commit()

    return jsonify({'message': 'Queue reset successfully. New customers start from #1.'})


@app.route('/api/pause', methods=['POST'])
@require_admin
def pause_queue():
    data = request.get_json()
    reason = data.get('reason', 'break')

    valid_reasons = ['lunch', 'break', 'prayer', 'busy']
    if reason not in valid_reasons:
        return jsonify({'error': f'Invalid reason. Valid: {", ".join(valid_reasons)}'}), 400

    db = get_db()
    shop = db.execute("SELECT * FROM shops WHERE id = ?", (g.shop_id,)).fetchone()
    if not shop:
        return jsonify({'error': 'Shop not found'}), 404

    db.execute("UPDATE shops SET is_paused = 1, pause_reason = ? WHERE id = ?", (reason, g.shop_id))
    db.commit()

    return jsonify({'message': 'Queue paused', 'reason': reason})


@app.route('/api/resume', methods=['POST'])
@require_admin
def resume_queue():
    db = get_db()
    shop = db.execute("SELECT * FROM shops WHERE id = ?", (g.shop_id,)).fetchone()
    if not shop:
        return jsonify({'error': 'Shop not found'}), 404

    db.execute("UPDATE shops SET is_paused = 0, pause_reason = NULL WHERE id = ?", (g.shop_id,))
    db.commit()

    return jsonify({'message': 'Queue resumed'})


@app.route('/api/toggle-open', methods=['POST'])
@require_admin
def toggle_open():
    db = get_db()
    shop = db.execute("SELECT * FROM shops WHERE id = ?", (g.shop_id,)).fetchone()
    if not shop:
        return jsonify({'error': 'Shop not found'}), 404
    new_status = 0 if shop['is_open'] else 1
    db.execute("UPDATE shops SET is_open = ? WHERE id = ?", (new_status, g.shop_id))
    db.commit()
    return jsonify({'is_open': bool(new_status), 'message': 'Shop is now ' + ('open' if new_status else 'closed')})


@app.route('/api/shop/info', methods=['GET'])
def get_shop_info():
    shop_id = request.args.get('shop_id', 1, type=int)
    db = get_db()
    shop = db.execute("SELECT * FROM shops WHERE id = ?", (shop_id,)).fetchone()
    if not shop:
        return jsonify({'error': 'Shop not found'}), 404
    return jsonify({
        'id': shop['id'],
        'name': shop['name'],
        'is_open': bool(shop['is_open']),
        'is_paused': bool(shop['is_paused']),
        'pause_reason': shop['pause_reason'],
        'avg_haircut_minutes': shop['avg_haircut_minutes'],
        'instagram': shop['instagram'],
        'facebook': shop['facebook'],
        'youtube': shop['youtube'],
        'whatsapp': shop['whatsapp'],
        'phone': shop['phone'],
        'location': shop['location'],
        'working_hours': shop['working_hours'],
        'hero_title': shop['hero_title'],
        'hero_desc': shop['hero_desc']
    })


@app.route('/api/stats', methods=['GET'])
@require_admin
def get_stats():
    period = request.args.get('period', 'day')

    db = get_db()
    shop = db.execute("SELECT * FROM shops WHERE id = ?", (g.shop_id,)).fetchone()
    if not shop:
        return jsonify({'error': 'Shop not found'}), 404

    if period == 'day':
        date_filter = "DATE(created_at) = DATE('now')"
    elif period == 'week':
        date_filter = "created_at >= datetime('now', '-7 days')"
    elif period == 'month':
        date_filter = "strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')"
    elif period == 'year':
        date_filter = "strftime('%Y', created_at) = strftime('%Y', 'now')"
    else:
        return jsonify({'error': 'Invalid period. Use: day, week, month, year'}), 400

    rows = db.execute(
        f"SELECT status, COUNT(*) as cnt FROM queue WHERE shop_id = ? AND {date_filter} GROUP BY status",
        (g.shop_id,)
    ).fetchall()

    stats = {'completed': 0, 'skipped': 0, 'left': 0, 'waiting': 0, 'current': 0, 'total': 0}
    for r in rows:
        stats[r['status']] = r['cnt']
    stats['total'] = stats['completed'] + stats['skipped'] + stats['left'] + stats['waiting'] + stats['current']

    period_label = {'day': "DATE(created_at)", 'week': "DATE(created_at)", 'month': "DATE(created_at)", 'year': "strftime('%Y-%m', created_at)"}
    group_key = period_label.get(period, "DATE(created_at)")
    group_label = 'date' if period in ('day', 'week', 'month') else 'month'

    detail = db.execute(
        f"SELECT {group_key} as period, status, COUNT(*) as cnt FROM queue WHERE shop_id = ? AND {date_filter} GROUP BY period, status ORDER BY period",
        (g.shop_id,)
    ).fetchall()

    detail_map = {}
    for r in detail:
        p = r['period']
        if p not in detail_map:
            detail_map[p] = {group_label: p, 'completed': 0, 'skipped': 0, 'left': 0, 'total': 0}
        if r['status'] in detail_map[p]:
            detail_map[p][r['status']] = r['cnt']
        detail_map[p]['total'] += r['cnt']

    stats['breakdown'] = sorted(detail_map.values(), key=lambda x: x[group_label])

    trend_filter = "created_at >= datetime('now', '-30 days')"
    trend_data = db.execute(
        f"SELECT DATE(created_at) as date, status, COUNT(*) as cnt FROM queue WHERE shop_id = ? AND {trend_filter} GROUP BY date, status ORDER BY date",
        (g.shop_id,)
    ).fetchall()
    trend_map = {}
    for r in trend_data:
        d = r['date']
        if d not in trend_map:
            trend_map[d] = {'date': d, 'completed': 0, 'skipped': 0, 'left': 0, 'total': 0}
        if r['status'] in trend_map[d]:
            trend_map[d][r['status']] = r['cnt']
        trend_map[d]['total'] += r['cnt']
    stats['trend'] = sorted(trend_map.values(), key=lambda x: x['date'])

    return jsonify(stats)


@app.route('/api/shop/update', methods=['POST'])
@require_admin
def update_shop():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    allowed = ['name', 'instagram', 'facebook', 'youtube', 'whatsapp', 'phone', 'location', 'working_hours', 'hero_title', 'hero_desc', 'avg_haircut_minutes']
    db = get_db()
    shop = db.execute("SELECT * FROM shops WHERE id = ?", (g.shop_id,)).fetchone()
    if not shop:
        return jsonify({'error': 'Shop not found'}), 404

    validations = {
        'name': ('Shop name', 1, 100),
        'instagram': ('Instagram URL', 0, 200),
        'facebook': ('Facebook URL', 0, 200),
        'youtube': ('YouTube URL', 0, 200),
        'whatsapp': ('WhatsApp URL', 0, 200),
        'phone': ('Phone number', 0, 50),
        'location': ('Location', 0, 300),
        'working_hours': ('Working hours', 0, 200),
        'hero_title': ('Hero title', 0, 200),
        'hero_desc': ('Hero description', 0, 500),
    }

    for key in allowed:
        if key not in data:
            continue
        val = data[key]
        if key == 'avg_haircut_minutes':
            err = validate_int(val, 'Average haircut time', 5, 120)
            if err:
                return jsonify({'error': err}), 400
            db.execute("UPDATE shops SET avg_haircut_minutes = ? WHERE id = ?", (val, g.shop_id))
        elif key in validations:
            label, min_l, max_l = validations[key]
            err = validate_string(val, label, min_l, max_l)
            if err:
                return jsonify({'error': err}), 400
            safe_val = sanitize_input(val, max_length=max_l) if val else val
            db.execute(f"UPDATE shops SET {key} = ? WHERE id = ?", (safe_val, g.shop_id))

    db.commit()
    return jsonify({'message': 'Shop updated successfully'})


@app.route('/api/dashboard', methods=['GET'])
@require_admin
def get_dashboard():
    db = get_db()
    shop = db.execute("SELECT * FROM shops WHERE id = ?", (g.shop_id,)).fetchone()
    if not shop:
        return jsonify({'error': 'Shop not found'}), 404

    stats = db.execute("""
        SELECT status, COUNT(*) as count FROM queue
        WHERE shop_id = ? AND DATE(created_at) = DATE('now')
        GROUP BY status
    """, (g.shop_id,)).fetchall()

    stat_map = {'completed': 0, 'skipped': 0, 'left': 0, 'waiting': 0, 'current': 0}
    for s in stats:
        stat_map[s['status']] = s['count']

    all_barbers = db.execute(
        "SELECT * FROM barbers WHERE shop_id = ? AND active = 1",
        (g.shop_id,)
    ).fetchall()

    barber = db.execute(
        "SELECT * FROM barbers WHERE user_id = ? AND shop_id = ? AND active = 1",
        (g.admin['id'], g.shop_id)
    ).fetchone()

    current = None
    if barber:
        current = db.execute(
            "SELECT * FROM queue WHERE shop_id = ? AND assigned_barber_id = ? AND status = 'current'",
            (g.shop_id, barber['id'])
        ).fetchone()

    barber_list = []
    for b in all_barbers:
        b_current = None
        bc = db.execute(
            "SELECT q.id, q.customer_name, q.queue_number, q.position FROM queue q "
            "WHERE q.shop_id = ? AND q.assigned_barber_id = ? AND q.status = 'current'",
            (g.shop_id, b['id'])
        ).fetchone()
        if bc:
            b_current = dict(bc)
        barber_list.append({
            'id': b['id'],
            'user_id': b['user_id'],
            'display_name': b['display_name'],
            'status': b['status'],
            'on_shift': bool(b['on_shift']),
            'auto_assign': bool(b['auto_assign']),
            'current_customer': b_current
        })

    waiting = db.execute(
        "SELECT * FROM queue WHERE shop_id = ? AND status = 'waiting' ORDER BY position LIMIT 5",
        (g.shop_id,)
    ).fetchall()

    return jsonify({
        'user_id': g.admin['id'],
        'shop': {
            'id': shop['id'],
            'name': shop['name'],
            'is_open': bool(shop['is_open']),
            'is_paused': bool(shop['is_paused']),
            'pause_reason': shop['pause_reason'],
            'avg_haircut_minutes': shop['avg_haircut_minutes'],
            'instagram': shop['instagram'],
            'facebook': shop['facebook'],
            'youtube': shop['youtube'],
            'whatsapp': shop['whatsapp'],
            'phone': shop['phone'],
            'location': shop['location'],
            'working_hours': shop['working_hours'],
            'hero_title': shop['hero_title'],
            'hero_desc': shop['hero_desc']
        },
        'barbers': barber_list,
        'current_customer': {
            'id': current['id'],
            'customer_name': current['customer_name'],
            'queue_number': current['queue_number'],
            'position': current['position']
        } if current else None,
        'next_customers': [{
            'id': e['id'],
            'customer_name': e['customer_name'],
            'queue_number': e['queue_number'],
            'position': e['position']
        } for e in waiting],
        'stats': {
            'completed_today': stat_map['completed'],
            'skipped_today': stat_map['skipped'],
            'left_today': stat_map['left'],
            'waiting_now': stat_map['waiting'],
            'total_served_today': stat_map['completed'] + stat_map['skipped'],
            'avg_service_time': shop['avg_haircut_minutes']
        }
    })


@app.route('/api/barber/take-next', methods=['POST'])
@require_barber
def barber_take_next():
    entry, err = take_next(g.barber['id'], g.shop_id)
    if err:
        return jsonify({'error': err}), 400
    return jsonify({
        'message': 'Now serving',
        'customer': {
            'id': entry['id'],
            'customer_name': entry['customer_name'],
            'queue_number': entry['queue_number']
        }
    })


@app.route('/api/barber/finish-next', methods=['POST'])
@require_barber
def barber_finish_next():
    barber = g.barber
    completed, err = finish_current(barber['id'], g.shop_id)
    if err:
        return jsonify({'error': err}), 400
    recalc_positions(g.shop_id)
    take_next(barber['id'], g.shop_id)
    return jsonify({'message': 'Finished and took next', 'customer': completed['customer_name']})


@app.route('/api/barber/pause', methods=['POST'])
@require_barber
def barber_pause():
    db = get_db()
    barber = g.barber
    existing = db.execute(
        "SELECT id FROM queue WHERE shop_id = ? AND assigned_barber_id = ? AND status = 'current'",
        (g.shop_id, barber['id'])
    ).fetchone()
    if existing:
        return jsonify({'error': 'Finish current customer before pausing'}), 400
    db.execute(
        "UPDATE barbers SET status = 'paused' WHERE id = ? AND shop_id = ?",
        (barber['id'], g.shop_id)
    )
    db.commit()
    return jsonify({'message': 'Barber paused'})


@app.route('/api/barber/resume', methods=['POST'])
@require_barber
def barber_resume():
    db = get_db()
    db.execute(
        "UPDATE barbers SET status = 'available' WHERE id = ? AND shop_id = ?",
        (g.barber['id'], g.shop_id)
    )
    db.commit()
    auto_take_next(g.shop_id)
    return jsonify({'message': 'Barber resumed'})


@app.route('/api/barber/start-shift', methods=['POST'])
@require_admin
def barber_start_shift():
    db = get_db()

    existing = db.execute(
        "SELECT * FROM barbers WHERE user_id = ? AND shop_id = ? AND active = 1",
        (g.admin['id'], g.shop_id)
    ).fetchone()
    if existing:
        db.execute(
            "UPDATE barbers SET on_shift = 1, status = 'available' WHERE id = ? AND shop_id = ?",
            (existing['id'], g.shop_id)
        )
    else:
        display_name = g.admin['username'].capitalize()
        cur = db.execute(
            "INSERT INTO barbers (shop_id, user_id, display_name, status, active, on_shift, auto_assign) VALUES (?, ?, ?, 'available', 1, 1, 1)",
            (g.shop_id, g.admin['id'], display_name)
        )
    db.commit()
    auto_take_next(g.shop_id)
    return jsonify({'message': 'Shift started'})


@app.route('/api/barber/end-shift', methods=['POST'])
@require_barber
def barber_end_shift():
    db = get_db()
    barber = g.barber
    existing = db.execute(
        "SELECT id FROM queue WHERE shop_id = ? AND assigned_barber_id = ? AND status = 'current'",
        (g.shop_id, barber['id'])
    ).fetchone()
    if existing:
        return jsonify({'error': 'Finish current customer before ending shift'}), 400
    db.execute(
        "UPDATE barbers SET on_shift = 0, status = 'offline' WHERE id = ? AND shop_id = ?",
        (barber['id'], g.shop_id)
    )
    db.commit()
    return jsonify({'message': 'Shift ended'})


@app.route('/api/admin/assistants', methods=['GET', 'POST'])
@require_owner
def handle_assistants():
    if request.method == 'GET':
        db = get_db()
        rows = db.execute(
            """SELECT u.id, u.username, u.active, u.created_at,
                      b.id as barber_id, b.display_name, b.status
               FROM users u
               LEFT JOIN barbers b ON b.user_id = u.id AND b.shop_id = u.shop_id
               WHERE u.shop_id = ? AND u.role = 'assistant'
               ORDER BY u.created_at DESC""",
            (g.shop_id,)
        ).fetchall()
        return jsonify({'assistants': [{
            'id': r['id'],
            'username': r['username'],
            'active': bool(r['active']),
            'display_name': r['display_name'],
            'barber_status': r['status'],
            'created_at': r['created_at']
        } for r in rows]})

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    display_name = data.get('display_name', '').strip() or username.capitalize()

    err = validate_string(username, 'Username', 3, 50)
    if err:
        return jsonify({'error': err}), 400
    err = validate_string(password, 'Password', 8, 200)
    if err:
        return jsonify({'error': err}), 400
    err = validate_string(display_name, 'Display name', 1, 50)
    if err:
        return jsonify({'error': err}), 400

    username = sanitize_input(username, max_length=50)
    display_name = sanitize_input(display_name, max_length=50)

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (shop_id, username, password, role, active) VALUES (?, ?, ?, 'assistant', 1)",
            (g.shop_id, username, hash_password(password))
        )
        user_id = cur.lastrowid
        db.execute(
            "INSERT INTO barbers (shop_id, user_id, display_name, status, active, auto_assign) VALUES (?, ?, ?, 'available', 1, 0)",
            (g.shop_id, user_id, display_name)
        )
        db.commit()
        logger.info(f"Assistant created: {username} (id={user_id}) by owner {g.admin['id']}")
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409

    return jsonify({'message': 'Assistant created', 'id': user_id}), 201


@app.route('/api/admin/assistants/<int:assistant_id>/deactivate', methods=['POST'])
@require_owner
def deactivate_assistant(assistant_id):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ? AND shop_id = ? AND role = 'assistant'",
        (assistant_id, g.shop_id)
    ).fetchone()
    if not user:
        return jsonify({'error': 'Assistant not found'}), 404
    db.execute("UPDATE users SET active = 0 WHERE id = ?", (assistant_id,))
    db.execute(
        "UPDATE barbers SET active = 0, status = 'offline' WHERE user_id = ? AND shop_id = ?",
        (assistant_id, g.shop_id)
    )
    db.commit()
    logger.info(f"Assistant deactivated: {user['username']} (id={assistant_id}) by owner {g.admin['id']}")
    return jsonify({'message': 'Assistant deactivated'})


@app.route('/api/admin/assistants/<int:assistant_id>/reactivate', methods=['POST'])
@require_owner
def reactivate_assistant(assistant_id):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ? AND shop_id = ? AND role = 'assistant'",
        (assistant_id, g.shop_id)
    ).fetchone()
    if not user:
        return jsonify({'error': 'Assistant not found'}), 404
    db.execute("UPDATE users SET active = 1 WHERE id = ?", (assistant_id,))
    db.execute(
        "UPDATE barbers SET active = 1, status = 'available' WHERE user_id = ? AND shop_id = ?",
        (assistant_id, g.shop_id)
    )
    db.commit()
    logger.info(f"Assistant reactivated: {user['username']} (id={assistant_id}) by owner {g.admin['id']}")
    return jsonify({'message': 'Assistant reactivated'})


@app.route('/api/admin/assistants/<int:assistant_id>/delete', methods=['POST'])
@require_owner
def delete_assistant(assistant_id):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ? AND shop_id = ? AND role = 'assistant'",
        (assistant_id, g.shop_id)
    ).fetchone()
    if not user:
        return jsonify({'error': 'Assistant not found'}), 404
    db.execute("DELETE FROM barbers WHERE user_id = ? AND shop_id = ?", (assistant_id, g.shop_id))
    db.execute("DELETE FROM users WHERE id = ?", (assistant_id,))
    db.commit()
    logger.info(f"Assistant deleted: {user['username']} (id={assistant_id}) by owner {g.admin['id']}")
    return jsonify({'message': 'Assistant permanently deleted'})


@app.route('/api/admin/assistants/<int:assistant_id>/change-password', methods=['POST'])
@require_owner
def change_assistant_password(assistant_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400
    new_password = data.get('new_password', '').strip()
    err = validate_string(new_password, 'New password', 8, 200)
    if err:
        return jsonify({'error': err}), 400
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ? AND shop_id = ? AND role = 'assistant'",
        (assistant_id, g.shop_id)
    ).fetchone()
    if not user:
        return jsonify({'error': 'Assistant not found'}), 404
    db.execute("UPDATE users SET password = ? WHERE id = ?",
               (hash_password(new_password), assistant_id))
    db.commit()
    logger.info(f"Password changed for assistant: {user['username']} (id={assistant_id}) by owner {g.admin['id']}")
    return jsonify({'message': 'Password updated successfully'})


@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        return jsonify({}), 200


@app.before_request
def validate_json_api_requests():
    if request.method not in ('POST', 'PUT', 'PATCH'):
        return
    if request.path == '/api/admin/login':
        return
    if request.content_type == 'application/json':
        return
    if not request.path.startswith('/api/'):
        return
    if not request.data:
        return
    return jsonify({'error': 'Content-Type must be application/json'}), 415


@app.before_request
def scp_system_lock():
    if request.method == 'OPTIONS':
        return
    if request.path.startswith('/scp/'):
        return
    if not request.path.startswith('/api/'):
        return
    try:
        db = get_db()
        row = db.execute("SELECT is_stopped FROM system_control WHERE id = 1").fetchone()
        if row and row['is_stopped']:
            return send_from_directory(CLIENT_DIR, 'stope.html')
    except Exception:
        pass


@app.route('/')
def index():
    return send_from_directory(CLIENT_DIR, 'index.html')


@app.route('/assets/<path:filename>')
def serve_client_assets(filename):
    safe_name = os.path.normpath(filename)
    if safe_name.startswith('..') or '..' in safe_name.split(os.sep):
        return jsonify({"success": False, "message": "Not found"}), 404
    assets_dir = os.path.join(CLIENT_DIR, 'assets')
    file_path = os.path.join(assets_dir, safe_name)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return send_from_directory(assets_dir, safe_name)
    return jsonify({"success": False, "message": "Not found"}), 404


@app.route('/<path:subpath>')
def serve_client_static(subpath):
    safe_subpath = os.path.normpath(subpath)
    if safe_subpath.startswith('..') or '..' in safe_subpath.split(os.sep):
        return jsonify({"success": False, "message": "Not found"}), 404
    if safe_subpath.startswith('api/'):
        return jsonify({"success": False, "message": "Not found"}), 404
    if safe_subpath.startswith('icons/') or safe_subpath in ('manifest.json',):
        file_path = os.path.join(CLIENT_DIR, safe_subpath)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return send_from_directory(CLIENT_DIR, safe_subpath)
    return send_from_directory(CLIENT_DIR, 'index.html')


if __name__ == '__main__':
    init_db()
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    if debug_mode:
        logger.warning("FLASK_DEBUG is enabled - do not use in production")
    app.run(debug=debug_mode, port=5000)
