from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import requests
from requests.auth import HTTPBasicAuth
import os
from dotenv import load_dotenv
import ldap3
from ldap3 import Server, Connection, ALL, NTLM

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Authentication Configuration
AUTH_ENABLED = os.getenv('AUTH_ENABLED', 'true').lower() == 'true'
FALLBACK_USERNAME = os.getenv('FALLBACK_USERNAME')
FALLBACK_PASSWORD = os.getenv('FALLBACK_PASSWORD')

# LDAP Configuration
LDAP_SERVER = os.getenv('LDAP_SERVER')
LDAP_PORT = int(os.getenv('LDAP_PORT', '389'))
LDAP_USE_SSL = os.getenv('LDAP_USE_SSL', 'false').lower() == 'true'
LDAP_DOMAIN = os.getenv('LDAP_DOMAIN')  # e.g., 'COMPANY'
LDAP_BASE_DN = os.getenv('LDAP_BASE_DN')  # e.g., 'DC=company,DC=local'
LDAP_USER_FILTER = os.getenv('LDAP_USER_FILTER', '(sAMAccountName={username})')
LDAP_ALLOWED_GROUPS = os.getenv('LDAP_ALLOWED_GROUPS')  # Comma-separated group names

# Icinga2 API Configuration
ICINGA_URL = os.getenv('ICINGA_URL')
ICINGA_USER = os.getenv('ICINGA_USER')
ICINGA_PASSWORD = os.getenv('ICINGA_PASSWORD')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
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
                return redirect(url_for('login', next=request.url))
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
        print("LDAP server not configured")
        return None
    
    try:
        # Create LDAP server connection
        server = Server(
            LDAP_SERVER,
            port=LDAP_PORT,
            use_ssl=LDAP_USE_SSL,
            get_info=ALL
        )
        
        # Try authentication with NTLM (domain\username format)
        if LDAP_DOMAIN:
            user_dn = f"{LDAP_DOMAIN}\\{username}"
        else:
            user_dn = f"{username}@{LDAP_BASE_DN}"
        
        # Attempt to bind (authenticate)
        conn = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=NTLM if LDAP_DOMAIN else ldap3.SIMPLE,
            auto_bind=True
        )
        
        # If bind successful, fetch user details
        user_info = {'username': username, 'display_name': username, 'email': None}
        
        if LDAP_BASE_DN:
            # Search for user details
            search_filter = LDAP_USER_FILTER.format(username=username)
            conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=search_filter,
                attributes=['displayName', 'mail', 'sAMAccountName', 'cn', 'memberOf']
            )
            
            if conn.entries:
                entry = conn.entries[0]
                user_info['display_name'] = str(entry.displayName) if hasattr(entry, 'displayName') else username
                user_info['email'] = str(entry.mail) if hasattr(entry, 'mail') else None
                
                # Check group membership if LDAP_ALLOWED_GROUPS is configured
                if LDAP_ALLOWED_GROUPS:
                    allowed_groups = [g.strip() for g in LDAP_ALLOWED_GROUPS.split(',')]
                    user_groups = []
                    
                    if hasattr(entry, 'memberOf'):
                        # Extract group names from DN format
                        for group_dn in entry.memberOf:
                            # Extract CN from DN (e.g., "CN=Admins,OU=Groups,DC=company,DC=local" -> "Admins")
                            group_parts = str(group_dn).split(',')[0].split('=')
                            if len(group_parts) > 1:
                                user_groups.append(group_parts[1])
                    
                    # Check if user is in any allowed group
                    if not any(group in allowed_groups for group in user_groups):
                        print(f"User {username} not in allowed groups. User groups: {user_groups}, Allowed: {allowed_groups}")
                        conn.unbind()
                        return None
        
        conn.unbind()
        return user_info
        
    except ldap3.core.exceptions.LDAPBindError:
        print(f"LDAP authentication failed for user: {username}")
        return None
    except Exception as e:
        print(f"LDAP error: {e}")
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
        self.headers = {
            'Accept': 'application/json',
            'X-HTTP-Method-Override': 'GET'
        }
    
    def _request(self, endpoint, method='GET', data=None):
        """Make API request to Icinga2"""
        url = f"{self.url}/v1/{endpoint}"
        try:
            response = requests.request(
                method,
                url,
                auth=self.auth,
                headers=self.headers,
                json=data,
                verify=False  # Disable SSL verification - set to True in production
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
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


# Initialize API client
icinga = Icinga2API(ICINGA_URL, ICINGA_USER, ICINGA_PASSWORD)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # If authentication is disabled, auto-login as guest
    if not AUTH_ENABLED:
        user = User(username='guest', display_name='Guest User')
        session['user_data'] = {'username': 'guest', 'display_name': 'Guest User', 'email': None}
        login_user(user)
        return redirect(url_for('dashboard'))
    
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return render_template('login.html', auth_enabled=AUTH_ENABLED)
        
        user_info = None
        auth_method = None
        
        # Try LDAP authentication first
        if LDAP_SERVER:
            user_info = authenticate_ldap(username, password)
            if user_info:
                auth_method = 'LDAP'
        
        # If LDAP failed or not configured, try fallback credentials
        if not user_info and FALLBACK_USERNAME:
            user_info = authenticate_fallback(username, password)
            if user_info:
                auth_method = 'Fallback'
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
            flash(f'Welcome, {user.display_name}!', 'success')
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    
    return render_template('login.html', auth_enabled=AUTH_ENABLED)


@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
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
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')


@app.route('/api/stats')
@optional_login_required
def api_stats():
    """Get statistics"""
    stats = icinga.get_stats()
    return jsonify(stats)


@app.route('/api/hosts')
@optional_login_required
def api_hosts():
    """Get all hosts"""
    hosts = icinga.get_hosts()
    return jsonify(hosts)


@app.route('/api/services')
@optional_login_required
def api_services():
    """Get all services"""
    services = icinga.get_services()
    return jsonify(services)


@app.route('/api/problems')
@optional_login_required
def api_problems():
    """Get all problems"""
    host_problems = icinga.get_host_problems()
    service_problems = icinga.get_service_problems()
    return jsonify({
        'hosts': host_problems,
        'services': service_problems
    })


@app.route('/hosts')
@app.route('/hosts/<state_filter>')
@optional_login_required
def hosts_overview(state_filter='all'):
    """Hosts overview page filtered by state"""
    return render_template('hosts_overview.html', state_filter=state_filter)


@app.route('/api/hosts/filter/<state_filter>')
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


@app.route('/services')
@app.route('/services/<state_filter>')
@optional_login_required
def services_overview(state_filter='all'):
    """Services overview page filtered by state"""
    return render_template('services_overview.html', state_filter=state_filter)


@app.route('/api/services/filter/<state_filter>')
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


@app.route('/host/<hostname>')
@optional_login_required
def host_details(hostname):
    """Host details page"""
    return render_template('host_details.html', hostname=hostname)


@app.route('/api/host/<hostname>')
@optional_login_required
def api_host_details(hostname):
    """Get detailed information for a specific host"""
    host = icinga.get_host_by_name(hostname)
    services = icinga.get_host_services(hostname)
    return jsonify({
        'host': host,
        'services': services
    })


@app.route('/service/<hostname>/<path:servicename>')
@optional_login_required
def service_details(hostname, servicename):
    """Service details page"""
    return render_template('service_details.html', hostname=hostname, servicename=servicename)


@app.route('/api/service/<hostname>/<path:servicename>')
@optional_login_required
def api_service_details(hostname, servicename):
    """Get detailed information for a specific service"""
    service = icinga.get_service_by_name(hostname, servicename)
    host = icinga.get_host_by_name(hostname)
    return jsonify({
        'service': service,
        'host': host
    })
    return jsonify({
        'host': host,
        'services': services
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
