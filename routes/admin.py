import secrets
import logging
from flask import Blueprint, request, jsonify, g, session
from database import get_db, check_password, hash_password, upgrade_password_hash
from functools import wraps
from utils import sanitize_input

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


def require_admin_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_id = session.get('admin_id')
        if not admin_id:
            return jsonify({'error': 'Authentication required'}), 401
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (admin_id,)).fetchone()
        if not user:
            session.clear()
            return jsonify({'error': 'Admin not found'}), 401
        g.admin = user
        return f(*args, **kwargs)
    return decorated


admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


@admin_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    err = validate_string(username, 'Username', 1, 100)
    if err:
        return jsonify({'error': err}), 400
    err = validate_string(password, 'Password', 1, 200)
    if err:
        return jsonify({'error': err}), 400

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user or not check_password(user['password'], password):
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({'error': 'Invalid username or password'}), 401

    if not user['active']:
        logger.warning(f"Login attempt for disabled account: {username}")
        return jsonify({'error': 'Account is disabled'}), 401

    upgrade_password_hash(db, user['id'], user['password'], password)

    session.clear()
    session.permanent = True
    session['admin_id'] = user['id']
    session['admin_username'] = user['username']
    session['csrf_token'] = secrets.token_hex(32)

    return jsonify({
        'message': 'Login successful',
        'username': user['username'],
        'id': user['id'],
        'role': user['role'],
        'csrf_token': session['csrf_token']
    })


@admin_bp.route('/change-password', methods=['POST'])
@require_admin_session
def change_password():
    admin = g.admin
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    err = validate_string(current_password, 'Current password', 1)
    if err:
        return jsonify({'error': err}), 400
    err = validate_string(new_password, 'New password', 8, 200)
    if err:
        return jsonify({'error': err}), 400

    if not check_password(admin['password'], current_password):
        return jsonify({'error': 'Current password is incorrect'}), 401

    db = get_db()
    db.execute("UPDATE users SET password = ? WHERE id = ?",
               (hash_password(new_password), admin['id']))
    db.commit()

    return jsonify({'message': 'Password changed successfully'})


@admin_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})


@admin_bp.route('/me', methods=['GET'])
def me():
    admin_id = session.get('admin_id')
    if not admin_id:
        return jsonify({'authenticated': False}), 200
    db = get_db()
    user = db.execute("SELECT id, username, role, shop_id FROM users WHERE id = ? AND active = 1", (admin_id,)).fetchone()
    if not user:
        session.clear()
        return jsonify({'authenticated': False}), 200
    return jsonify({'authenticated': True, 'id': user['id'], 'username': user['username'], 'role': user['role'], 'shop_id': user['shop_id']})
