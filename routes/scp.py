import logging
from flask import Blueprint, request, jsonify
from database import get_db
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)

scp_bp = Blueprint('scp', __name__, url_prefix='/scp')


def get_scp_state(db):
    return db.execute("SELECT * FROM system_control WHERE id = 1").fetchone()


@scp_bp.route('/setup', methods=['POST'])
def scp_setup():
    db = get_db()
    state = get_scp_state(db)

    if state and state['is_initialized']:
        return jsonify({'error': 'System already initialized'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    password = data.get('password', '')

    if not isinstance(password, str) or len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    pw_hash = generate_password_hash(password)

    if state:
        db.execute(
            "UPDATE system_control SET password_hash = ?, is_initialized = 1 WHERE id = 1",
            (pw_hash,)
        )
    else:
        db.execute(
            "INSERT INTO system_control (password_hash, is_initialized) VALUES (?, 1)",
            (pw_hash,)
        )

    db.commit()
    logger.info("SCP initialized successfully")
    return jsonify({'message': 'System Control Panel initialized successfully'}), 201


@scp_bp.route('/control', methods=['POST'])
def scp_control():
    db = get_db()
    state = get_scp_state(db)

    if not state or not state['is_initialized']:
        return jsonify({'error': 'System Control Panel not initialized'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    password = data.get('password', '')
    action = data.get('action', '')

    if not isinstance(action, str) or action not in ('start', 'stop', 'status'):
        return jsonify({'error': 'Invalid action. Use: start, stop, status'}), 400

    if not check_password_hash(state['password_hash'], password):
        return jsonify({'error': 'Invalid password'}), 401

    if action == 'start':
        db.execute("UPDATE system_control SET is_stopped = 0 WHERE id = 1")
        db.commit()
        logger.info("SCP: System started")
        return jsonify({'message': 'System started', 'is_stopped': False})

    if action == 'stop':
        db.execute("UPDATE system_control SET is_stopped = 1 WHERE id = 1")
        db.commit()
        logger.info("SCP: System stopped")
        return jsonify({'message': 'System stopped', 'is_stopped': True})

    if action == 'status':
        state = get_scp_state(db)
        return jsonify({
            'is_stopped': bool(state['is_stopped']),
            'is_initialized': bool(state['is_initialized'])
        })

    return jsonify({'error': 'Invalid action'}), 400


@scp_bp.route('/change-password', methods=['POST'])
def scp_change_password():
    db = get_db()
    state = get_scp_state(db)

    if not state or not state['is_initialized']:
        return jsonify({'error': 'System Control Panel not initialized'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if not isinstance(current_password, str) or not current_password:
        return jsonify({'error': 'Current password is required'}), 400

    if not isinstance(new_password, str) or len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400

    if not check_password_hash(state['password_hash'], current_password):
        return jsonify({'error': 'Invalid current password'}), 401

    pw_hash = generate_password_hash(new_password)
    db.execute("UPDATE system_control SET password_hash = ? WHERE id = 1", (pw_hash,))
    db.commit()
    logger.info("SCP password changed")
    return jsonify({'message': 'Password updated successfully'})
