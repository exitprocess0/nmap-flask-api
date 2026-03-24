import os
import subprocess
import shlex
import sanitizer
import logging
from functools import wraps
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sanitizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "20 per hour"]
)

API_KEY = os.environ.get('API_KEY')
NMAP_SCRIPT = os.environ.get('NMAP_SCRIPT', './run-nmap.sh')
MAX_TIME = int(os.environ.get('MAX_SCAN_TIME', 300))

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        
        parts = auth.split()
        token = parts[1] if len(parts) == 2 and parts[0].lower() == 'bearer' else auth
        
        if not API_KEY:
            return jsonify({'error': 'Server not configured'}), 500
        
        if not token or token != API_KEY:
            logger.warning(f"Invalid auth attempt from {request.remote_addr}")
            return jsonify({'error': 'Unauthorized'}), 401
        
        return f(*args, **kwargs)
    return decorated


@app.route('/health')
def health():
    """Health check - no auth required."""
    return jsonify({
        'status': 'ok',
        'nmap_available': os.path.exists(NMAP_SCRIPT)
    })


@app.route('/scan', methods=['POST'])
@limiter.limit("10 per hour")
@require_auth
def scan():
    
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    
    data = request.get_json()
    args = data.get('args', [])
    
    if not isinstance(args, list) or not args:
        return jsonify({'error': 'args must be a non-empty list'}), 400
    
    clean_args, targets, error = sanitizer.sanitize(args)
    
    if error:
        logger.warning(f"Sanitization failed: {error}")
        return jsonify({
            'error': 'Invalid command',
            'message': error
        }), 400
    
    cmd = [NMAP_SCRIPT] + clean_args + targets
    logger.info(f"Running scan on {targets}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_TIME
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'return_code': result.returncode,
            'command': ' '.join(shlex.quote(c) for c in cmd),
            'targets': targets,
            'stdout': result.stdout,
            'stderr': result.stderr
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({
            'error': 'Timeout',
            'message': f'Scan exceeded {MAX_TIME} seconds'
        }), 504
        
    except FileNotFoundError:
        logger.error(f"Nmap script not found: {NMAP_SCRIPT}")
        return jsonify({'error': 'Nmap not available'}), 500
        
    except Exception as e:
        logger.exception("Scan failed")
        return jsonify({'error': str(e)}), 500


@app.route('/allowed', methods=['GET'])
@require_auth
def allowed():
    """Show allowed flags and scripts."""
    return jsonify({
        'bool_flags': sorted(list(sanitizer.BOOL_FLAGS)),
        'arg_flags': list(sanitizer.ARG_FLAGS.keys()),
        'scripts': sorted(list(sanitizer.ALLOWED_SCRIPTS)),
        'categories': sorted(list(sanitizer.ALLOWED_CATEGORIES))
    })


@app.errorhandler(429)
def rate_limit(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429
