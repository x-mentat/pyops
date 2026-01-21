from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, Blueprint
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
from requests.auth import HTTPBasicAuth
import os
from dotenv import load_dotenv
import ldap3
from ldap3 import Server, Connection, ALL, NTLM
import logging
from logging.handlers import RotatingFileHandler

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('pyops-dashboard.log', maxBytes=10485760, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Application prefix for reverse proxy support
APP_PREFIX = os.getenv('APP_PREFIX', '').rstrip('/')

logger.info("Starting PyOPS Dashboard application")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Apply ProxyFix middleware for reverse proxy support
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Create blueprint with prefix support
bp = Blueprint('main', __name__, url_prefix=APP_PREFIX if APP_PREFIX else None)

# Authentication Configuration
AUTH_ENABLED = os.getenv('AUTH_ENABLED', 'true').lower() == 'true'
FALLBACK_USERNAME = os.getenv('FALLBACK_USERNAME')
FALLBACK_PASSWORD = os.getenv('FALLBACK_PASSWORD')

logger.info(f"Authentication enabled: {AUTH_ENABLED}")

# LDAP Configuration
LDAP_SERVER = os.getenv('LDAP_SERVER')
LDAP_PORT = int(os.getenv('LDAP_PORT', '389'))
LDAP_USE_SSL = os.getenv('LDAP_USE_SSL', 'false').lower() == 'true'
LDAP_DOMAIN = os.getenv('LDAP_DOMAIN')  # e.g., 'COMPANY'
LDAP_BASE_DN = os.getenv('LDAP_BASE_DN')  # e.g., 'DC=company,DC=local'
LDAP_USER_FILTER = os.getenv('LDAP_USER_FILTER', '(sAMAccountName={username})')
LDAP_ALLOWED_GROUPS = os.getenv('LDAP_ALLOWED_GROUPS')  # Comma-separated group names

if LDAP_SERVER:
    logger.info(f"LDAP configured: {LDAP_SERVER}:{LDAP_PORT} (SSL: {LDAP_USE_SSL}, Domain: {LDAP_DOMAIN})")

# Icinga2 API Configuration
ICINGA_URL = os.getenv('ICINGA_URL')
ICINGA_USER = os.getenv('ICINGA_USER')
ICINGA_PASSWORD = os.getenv('ICINGA_PASSWORD')

logger.info(f"Icinga2 API configured: {ICINGA_URL}")

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'main.login'
login_manager.login_message = 'Please log in to access this page.'


class User(UserMixin):
    """User class for Flask-Login"""
    def __init__(self, username, display_name=None, email=None):
        self.id = username
        self.username = username
        self.display_name = display_name or username
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    """Load user from session"""
    if 'user_data' in session:
        user_data = session['user_data']
        return User(
            username=user_data.get('username'),
            display_name=user_data.get('display_name'),
            email=user_data.get('email')
        )
    return None


def optional_login_required(f):
    """Decorator that requires login only if authentication is enabled"""
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if AUTH_ENABLED and not current_user.is_authenticated:
            # Auto-create guest user if auth is disabled
            if not AUTH_ENABLED:
                user = User(username='guest', display_name='Guest User')
                session['user_data'] = {'username': 'guest', 'display_name': 'Guest User', 'email': None}
                login_user(user)
            else:
                return redirect(url_for('main.login', next=request.url))
        elif not AUTH_ENABLED and not current_user.is_authenticated:
            # Auto-login as guest when auth is disabled
            user = User(username='guest', display_name='Guest User')
            session['user_data'] = {'username': 'guest', 'display_name': 'Guest User', 'email': None}
            login_user(user)
        return f(*args, **kwargs)
    return decorated_function


def authenticate_ldap(username, password):
    """Authenticate user against Active Directory LDAP"""
    if not LDAP_SERVER:
        logger.warning("LDAP authentication attempted but LDAP server not configured")
        return None
    
    logger.info(f"LDAP authentication attempt for user: {username}")
    
    try:
        # Create LDAP server connection
        server = Server(
            LDAP_SERVER,
            port=LDAP_PORT,
            use_ssl=LDAP_USE_SSL,
            get_info=ALL
        )
        
        logger.debug(f"LDAP server object created: {LDAP_SERVER}:{LDAP_PORT} (SSL: {LDAP_USE_SSL})")
        
        # Try authentication with NTLM (domain\username format)
        if LDAP_DOMAIN:
            user_dn = f"{LDAP_DOMAIN}\\{username}"
            logger.debug(f"Using NTLM authentication with DN: {user_dn}")
        else:
            user_dn = f"{username}@{LDAP_BASE_DN}"
            logger.debug(f"Using SIMPLE authentication with DN: {user_dn}")
        
        # Attempt to bind (authenticate)
        logger.debug(f"Attempting LDAP bind for user: {username}")
        conn = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=NTLM if LDAP_DOMAIN else ldap3.SIMPLE,
            auto_bind=True
        )
        
        logger.info(f"LDAP bind successful for user: {username}")
        
        # If bind successful, fetch user details
        user_info = {'username': username, 'display_name': username, 'email': None}
        
        if LDAP_BASE_DN:
            # Search for user details
            search_filter = LDAP_USER_FILTER.format(username=username)
            logger.debug(f"Searching LDAP with filter: {search_filter} in base DN: {LDAP_BASE_DN}")
            
            conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=search_filter,
                attributes=['displayName', 'mail', 'sAMAccountName', 'cn', 'memberOf']
            )
            
            if conn.entries:
                entry = conn.entries[0]
                user_info['display_name'] = str(entry.displayName) if hasattr(entry, 'displayName') else username
                user_info['email'] = str(entry.mail) if hasattr(entry, 'mail') else None
                
                logger.info(f"LDAP user details found - Display name: {user_info['display_name']}, Email: {user_info['email']}")
                
                # Check group membership if LDAP_ALLOWED_GROUPS is configured
                if LDAP_ALLOWED_GROUPS:
                    allowed_groups = [g.strip() for g in LDAP_ALLOWED_GROUPS.split(',')]
                    user_groups = []
                    
                    logger.debug(f"Checking group membership. Allowed groups: {allowed_groups}")
                    if hasattr(entry, 'memberOf'):
                        # Extract group names from DN format
                        for group_dn in entry.memberOf:
                            # Extract CN from DN (e.g., "CN=Admins,OU=Groups,DC=company,DC=local" -> "Admins")
                            group_parts = str(group_dn).split(',')[0].split('=')
                            if len(group_parts) > 1:
                                user_groups.append(group_parts[1])
                    
                    logger.debug(f"User groups found: {user_groups}")
                    
                    # Check if user is in any allowed group
                    if not any(group in allowed_groups for group in user_groups):
                        logger.warning(f"LDAP authorization failed for user {username}. User groups: {user_groups}, Allowed groups: {allowed_groups}")
                        conn.unbind()
                        return None
                    
                    logger.info(f"User {username} authorized via group membership: {[g for g in user_groups if g in allowed_groups]}")
        
        conn.unbind()
        logger.info(f"LDAP authentication successful for user: {username}")
        return user_info
        
    except ldap3.core.exceptions.LDAPBindError as e:
        logger.error(f"LDAP bind failed for user {username}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"LDAP authentication error for user {username}: {str(e)}", exc_info=True)
        return None


def authenticate_fallback(username, password):
    """Fallback authentication using local credentials"""
    if FALLBACK_USERNAME and FALLBACK_PASSWORD:
        if username == FALLBACK_USERNAME and password == FALLBACK_PASSWORD:
            return {
                'username': username,
                'display_name': f'{username} (Fallback)',
                'email': None
            }
    return None


class Icinga2API:
    """Icinga2 API Client"""
    
    def __init__(self, url, username, password):
        self.url = url.rstrip('/')
        self.auth = HTTPBasicAuth(username, password)
    
    def _request(self, endpoint, method='GET', data=None):
        """Make API request to Icinga2"""
        url = f"{self.url}/v1/{endpoint}"
        
        # Build headers
        headers = {'Accept': 'application/json'}
        
        logger.debug(f"Icinga2 API request: {method} {url}")
        
        try:
            if method in ['POST', 'PUT']:
                # For POST/PUT requests, send data as JSON body
                response = requests.request(
                    method,
                    url,
                    auth=self.auth,
                    headers=headers,
                    json=data,
                    verify=False
                )
            else:
                # For GET requests with filters, use X-HTTP-Method-Override
                if data:
                    headers['X-HTTP-Method-Override'] = 'GET'
                response = requests.request(
                    method,
                    url,
                    auth=self.auth,
                    headers=headers,
                    json=data,
                    verify=False
                )
            
            response.raise_for_status()
            logger.debug(f"Icinga2 API request successful: {method} {endpoint}")
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Icinga2 API request failed: {method} {url} - {str(e)}")
            return None
    
    def get_hosts(self, state=None):
        """Get all hosts, optionally filtered by state"""
        if state is not None:
            data = {'filter': f'host.state == {state}'}
            response = self._request('objects/hosts', data=data)
        else:
            response = self._request('objects/hosts')
        if response and 'results' in response:
            return response['results']
        return []
    
    def get_services(self, state=None):
        """Get all services, optionally filtered by state"""
        if state is not None:
            data = {'filter': f'service.state == {state}'}
            response = self._request('objects/services', data=data)
        else:
            response = self._request('objects/services')
        if response and 'results' in response:
            return response['results']
        return []
    
    def get_host_by_name(self, hostname):
        """Get detailed information for a specific host"""
        response = self._request(f'objects/hosts/{hostname}')
        if response and 'results' in response and len(response['results']) > 0:
            return response['results'][0]
        return None
    
    def get_host_services(self, hostname):
        """Get all services for a specific host"""
        data = {
            'filter': f'host.name == "{hostname}"'
        }
        response = self._request('objects/services', data=data)
        if response and 'results' in response:
            return response['results']
        return []
    
    def get_service_by_name(self, hostname, servicename):
        """Get detailed information for a specific service"""
        # Service name format in Icinga2 API: hostname!servicename
        service_full_name = f"{hostname}!{servicename}"
        response = self._request(f'objects/services/{service_full_name}')
        if response and 'results' in response and len(response['results']) > 0:
            return response['results'][0]
        return None
    
    def get_host_problems(self):
        """Get hosts with problems"""
        data = {
            'filter': 'host.state != 0',
            'attrs': ['name', 'state', 'last_check_result', 'acknowledgement']
        }
        response = self._request('objects/hosts', data=data)
        if response and 'results' in response:
            return response['results']
        return []
    
    def get_service_problems(self):
        """Get services with problems"""
        data = {
            'filter': 'service.state != 0',
            'attrs': ['name', 'host_name', 'state', 'last_check_result', 'acknowledgement']
        }
        response = self._request('objects/services', data=data)
        if response and 'results' in response:
            return response['results']
        return []
    
    def get_stats(self):
        """Get overall statistics"""
        hosts = self.get_hosts()
        services = self.get_services()
        
        host_stats = {
            'total': len(hosts),
            'up': 0,
            'down': 0,
            'unreachable': 0
        }
        
        service_stats = {
            'total': len(services),
            'ok': 0,
            'warning': 0,
            'critical': 0,
            'unknown': 0
        }
        
        for host in hosts:
            state = host.get('attrs', {}).get('state', 0)
            if state == 0:
                host_stats['up'] += 1
            elif state == 1:
                host_stats['down'] += 1
            elif state == 2:
                host_stats['unreachable'] += 1
        
        for service in services:
            state = service.get('attrs', {}).get('state', 0)
            if state == 0:
                service_stats['ok'] += 1
            elif state == 1:
                service_stats['warning'] += 1
            elif state == 2:
                service_stats['critical'] += 1
            elif state == 3:
                service_stats['unknown'] += 1
        
        return {
            'hosts': host_stats,
            'services': service_stats
        }
    
    def reschedule_host_check(self, hostname):
        """Trigger immediate check for a host"""
        import time
        data = {
            'type': 'Host',
            'filter': f'host.name == "{hostname}"',
            'next_check': time.time(),  # Schedule check for right now
            'force': True  # Force the check to run immediately
        }
        response = self._request('actions/reschedule-check', method='POST', data=data)
        return response
    
    def reschedule_service_check(self, hostname, servicename):
        """Trigger immediate check for a service"""
        import time
        service_full_name = f"{hostname}!{servicename}"
        data = {
            'type': 'Service',
            'filter': f'service.name == "{service_full_name}"',
            'next_check': time.time(),  # Schedule check for right now
            'force': True  # Force the check to run immediately
        }
        response = self._request('actions/reschedule-check', method='POST', data=data)
        return response
    
    def acknowledge_host_problem(self, hostname, author, comment):
        """Acknowledge a host problem"""
        data = {
            'type': 'Host',
            'filter': f'host.name == "{hostname}"',
            'author': author,
            'comment': comment,
            'sticky': True,
            'notify': True
        }
        response = self._request('actions/acknowledge-problem', method='POST', data=data)
        return response
    
    def acknowledge_service_problem(self, hostname, servicename, author, comment):
        """Acknowledge a service problem"""
        service_full_name = f"{hostname}!{servicename}"
        data = {
            'type': 'Service',
            'filter': f'service.name == "{service_full_name}"',
            'author': author,
            'comment': comment,
            'sticky': True,
            'notify': True
        }
        response = self._request('actions/acknowledge-problem', method='POST', data=data)
        return response
    
    def remove_host_acknowledgement(self, hostname):
        """Remove acknowledgement from a host"""
        data = {
            'type': 'Host',
            'filter': f'host.name == "{hostname}"'
        }
        response = self._request('actions/remove-acknowledgement', method='POST', data=data)
        return response
    
    def remove_service_acknowledgement(self, hostname, servicename):
        """Remove acknowledgement from a service"""
        service_full_name = f"{hostname}!{servicename}"
        data = {
            'type': 'Service',
            'filter': f'service.name == "{service_full_name}"'
        }
        response = self._request('actions/remove-acknowledgement', method='POST', data=data)
        return response


# Initialize API client
icinga = Icinga2API(ICINGA_URL, ICINGA_USER, ICINGA_PASSWORD)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # If authentication is disabled, auto-login as guest
    if not AUTH_ENABLED:
        logger.debug("Authentication disabled, auto-login as guest")
        user = User(username='guest', display_name='Guest User')
        session['user_data'] = {'username': 'guest', 'display_name': 'Guest User', 'email': None}
        login_user(user)
        return redirect(url_for('main.dashboard'))
    
    if current_user.is_authenticated:
        logger.debug(f"User {current_user.username} already authenticated, redirecting to dashboard")
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        logger.info(f"Login attempt for user: {username} from IP: {request.remote_addr}")
        
        if not username or not password:
            logger.warning(f"Login attempt with missing credentials from IP: {request.remote_addr}")
            flash('Please enter both username and password.', 'danger')
            return render_template('login.html', auth_enabled=AUTH_ENABLED)
        
        user_info = None
        auth_method = None
        
        # Try LDAP authentication first
        if LDAP_SERVER:
            logger.debug(f"Attempting LDAP authentication for user: {username}")
            user_info = authenticate_ldap(username, password)
            if user_info:
                auth_method = 'LDAP'
                logger.info(f"LDAP authentication successful for user: {username}")
        
        # If LDAP failed or not configured, try fallback credentials
        if not user_info and FALLBACK_USERNAME:
            logger.debug(f"Attempting fallback authentication for user: {username}")
            user_info = authenticate_fallback(username, password)
            if user_info:
                auth_method = 'Fallback'
                logger.info(f"Fallback authentication successful for user: {username}")
                flash('Using fallback authentication. LDAP may be unavailable.', 'warning')
        
        if user_info:
            user = User(
                username=user_info['username'],
                display_name=user_info['display_name'],
                email=user_info['email']
            )
            
            # Store user data in session
            session['user_data'] = user_info
            session['auth_method'] = auth_method
            
            # Log the user in
            login_user(user, remember=remember)
            logger.info(f"User {username} logged in successfully via {auth_method} from IP: {request.remote_addr}")
            flash(f'Welcome, {user.display_name}!', 'success')
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            logger.warning(f"Failed login attempt for user: {username} from IP: {request.remote_addr}")
            flash('Invalid username or password. Please try again.', 'danger')
    
    return render_template('login.html', auth_enabled=AUTH_ENABLED)


@bp.route('/logout')
@login_required
def logout():
    """Logout user"""
    username = current_user.username if current_user.is_authenticated else 'unknown'
    logger.info(f"User {username} logged out from IP: {request.remote_addr}")
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))


@bp.route('/')
def dashboard():
    """Main dashboard page"""
    # If authentication is disabled, allow direct access
    if not AUTH_ENABLED:
        # Create a guest user for the session
        if not current_user.is_authenticated:
            user = User(username='guest', display_name='Guest User')
            session['user_data'] = {'username': 'guest', 'display_name': 'Guest User', 'email': None}
            login_user(user)
    elif not current_user.is_authenticated:
        return redirect(url_for('main.login'))
    
    return render_template('dashboard.html')


@bp.route('/api/stats')
@optional_login_required
def api_stats():
    """Get statistics"""
    stats = icinga.get_stats()
    return jsonify(stats)


@bp.route('/api/hosts')
@optional_login_required
def api_hosts():
    """Get all hosts"""
    hosts = icinga.get_hosts()
    return jsonify(hosts)


@bp.route('/api/services')
@optional_login_required
def api_services():
    """Get all services"""
    services = icinga.get_services()
    return jsonify(services)


@bp.route('/api/problems')
@optional_login_required
def api_problems():
    """Get all problems"""
    host_problems = icinga.get_host_problems()
    service_problems = icinga.get_service_problems()
    return jsonify({
        'hosts': host_problems,
        'services': service_problems
    })


@bp.route('/hosts')
@bp.route('/hosts/<state_filter>')
@optional_login_required
def hosts_overview(state_filter='all'):
    """Hosts overview page filtered by state"""
    return render_template('hosts_overview.html', state_filter=state_filter)


@bp.route('/api/hosts/filter/<state_filter>')
@optional_login_required
def api_hosts_filtered(state_filter):
    """Get hosts filtered by state"""
    state_map = {
        'up': 0,
        'down': 1,
        'unreachable': 2
    }
    
    if state_filter == 'all':
        hosts = icinga.get_hosts()
    elif state_filter in state_map:
        hosts = icinga.get_hosts(state=state_map[state_filter])
    else:
        hosts = []
    
    return jsonify(hosts)


@bp.route('/services')
@bp.route('/services/<state_filter>')
@optional_login_required
def services_overview(state_filter='all'):
    """Services overview page filtered by state"""
    return render_template('services_overview.html', state_filter=state_filter)


@bp.route('/api/services/filter/<state_filter>')
@optional_login_required
def api_services_filtered(state_filter):
    """Get services filtered by state"""
    state_map = {
        'ok': 0,
        'warning': 1,
        'critical': 2,
        'unknown': 3
    }
    
    if state_filter == 'all':
        services = icinga.get_services()
    elif state_filter in state_map:
        services = icinga.get_services(state=state_map[state_filter])
    else:
        services = []
    
    return jsonify(services)


@bp.route('/host/<hostname>')
@optional_login_required
def host_details(hostname):
    """Host details page"""
    return render_template('host_details.html', hostname=hostname)


@bp.route('/api/host/<hostname>')
@optional_login_required
def api_host_details(hostname):
    """Get detailed information for a specific host"""
    host = icinga.get_host_by_name(hostname)
    services = icinga.get_host_services(hostname)
    return jsonify({
        'host': host,
        'services': services
    })


@bp.route('/api/host/<hostname>/check', methods=['POST'])
@optional_login_required
def api_trigger_host_check(hostname):
    """Trigger immediate check for a host"""
    result = icinga.reschedule_host_check(hostname)
    if result:
        return jsonify({'success': True, 'message': f'Check triggered for host {hostname}'})
    else:
        return jsonify({'success': False, 'message': 'Failed to trigger check'}), 500


@bp.route('/api/host/<hostname>/acknowledge', methods=['POST'])
@optional_login_required
def api_acknowledge_host(hostname):
    """Acknowledge a host problem"""
    data = request.get_json()
    comment = data.get('comment', 'Acknowledged via dashboard')
    author = current_user.username if current_user.is_authenticated else 'dashboard'
    
    result = icinga.acknowledge_host_problem(hostname, author, comment)
    if result:
        return jsonify({'success': True, 'message': f'Host {hostname} acknowledged'})
    else:
        return jsonify({'success': False, 'message': 'Failed to acknowledge'}), 500


@bp.route('/api/host/<hostname>/remove-acknowledgement', methods=['POST'])
@optional_login_required
def api_remove_host_acknowledgement(hostname):
    """Remove acknowledgement from a host"""
    result = icinga.remove_host_acknowledgement(hostname)
    if result:
        return jsonify({'success': True, 'message': f'Acknowledgement removed from host {hostname}'})
    else:
        return jsonify({'success': False, 'message': 'Failed to remove acknowledgement'}), 500


@bp.route('/service/<hostname>/<path:servicename>')
@optional_login_required
def service_details(hostname, servicename):
    """Service details page"""
    return render_template('service_details.html', hostname=hostname, servicename=servicename)


@bp.route('/api/service/<hostname>/<path:servicename>')
@optional_login_required
def api_service_details(hostname, servicename):
    """Get detailed information for a specific service"""
    service = icinga.get_service_by_name(hostname, servicename)
    host = icinga.get_host_by_name(hostname)
    return jsonify({
        'service': service,
        'host': host
    })


@bp.route('/api/service/<hostname>/<path:servicename>/check', methods=['POST'])
@optional_login_required
def api_trigger_service_check(hostname, servicename):
    """Trigger immediate check for a service"""
    result = icinga.reschedule_service_check(hostname, servicename)
    if result:
        return jsonify({'success': True, 'message': f'Check triggered for service {servicename}'})
    else:
        return jsonify({'success': False, 'message': 'Failed to trigger check'}), 500


@bp.route('/api/service/<hostname>/<path:servicename>/acknowledge', methods=['POST'])
@optional_login_required
def api_acknowledge_service(hostname, servicename):
    """Acknowledge a service problem"""
    data = request.get_json()
    comment = data.get('comment', 'Acknowledged via dashboard')
    author = current_user.username if current_user.is_authenticated else 'dashboard'
    
    result = icinga.acknowledge_service_problem(hostname, servicename, author, comment)
    if result:
        return jsonify({'success': True, 'message': f'Service {servicename} acknowledged'})
    else:
        return jsonify({'success': False, 'message': 'Failed to acknowledge'}), 500


@bp.route('/api/service/<hostname>/<path:servicename>/remove-acknowledgement', methods=['POST'])
@optional_login_required
def api_remove_service_acknowledgement(hostname, servicename):
    """Remove acknowledgement from a service"""
    result = icinga.remove_service_acknowledgement(hostname, servicename)
    if result:
        return jsonify({'success': True, 'message': f'Acknowledgement removed from service {servicename}'})
    else:
        return jsonify({'success': False, 'message': 'Failed to remove acknowledgement'}), 500


# Register blueprint
app.register_blueprint(bp)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
