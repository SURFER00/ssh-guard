import json, logging, paramiko, signal, sys
from flask import Flask, request, jsonify
from time import time
from waitress import serve

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# SSH Host class
class SSHHost:
    def __init__(self, name, hostname, username, private_key):
        self.name = name
        self.hostname = hostname
        self.username = username
        self.private_key = private_key

    @staticmethod
    def from_config(name, config):
        return SSHHost(
            name,
            config.get("hostname"),
            config.get("username"),
            config.get("private_key")
        )


# Command class
class SSHCommand:
    def __init__(self, name, command, description=""):
        self.name = name
        self.command = command
        self.description = description

    @staticmethod
    def from_config(name, config):
        return SSHCommand(
            name,
            config.get("command"),
            config.get("description", "")
        )


# API Token class
class APIToken:
    def __init__(self, token, allowed_servers, allowed_commands):
        self.token = token
        self.allowed_servers = allowed_servers
        self.allowed_commands = allowed_commands

    def can_access(self, server_name, command_name):
        return server_name in self.allowed_servers and command_name in self.allowed_commands

    @staticmethod
    def from_config(config):
        return APIToken(
            config.get("token"),
            config.get("permissions", {}).get("allowed_servers", []),
            config.get("permissions", {}).get("allowed_command_names", [])
        )


# SSH Executor class
class SSHExecutor:
    def __init__(self, host):
        self.host = host

    def run_command(self, command):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.host.hostname, username=self.host.username, key_filename=self.host.private_key)

        stdin, stdout, stderr = ssh.exec_command(command.command)
        output = stdout.read().decode('iso_8859_1')
        error = stderr.read().decode('iso_8859_1')

        ssh.close()
        return output, error


# API Manager class
class APIManager:
    def __init__(self, config_data):
        self.commands = {name: SSHCommand.from_config(name, cmd) for name, cmd in config_data.get("commands", {}).items()}
        self.hosts = {name: SSHHost.from_config(name, host) for name, host in config_data.get("ssh_servers", {}).items()}
        self.api_tokens = [APIToken.from_config(token) for token in config_data.get("api_tokens", [])]

    def get_token(self, token_value):
        return next((token for token in self.api_tokens if token.token == token_value), None)

    def get_command(self, command_name):
        return self.commands.get(command_name)

    def get_host(self, server_name):
        return self.hosts.get(server_name)

# IP Manager class
class IPManager:
    def __init__(self, block_time=300, max_attempts=3):
        self.block_time = block_time  # Duration to block IP in seconds
        self.max_attempts = max_attempts  # Maximum allowed attempts
        self.failed_attempts = {}  # Dictionary to track attempts

    def is_blocked(self, ip):
        if ip in self.failed_attempts:
            attempts, first_attempt_time = self.failed_attempts[ip]
            if attempts >= self.max_attempts:
                if time() - first_attempt_time < self.block_time:
                    return True  # IP is still blocked
                else:
                    del self.failed_attempts[ip]  # Remove expired block
        return False

    def register_failed_attempt(self, ip):
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = [1, time()]
        else:
            self.failed_attempts[ip][0] += 1  # Increment attempts

# API endpoint to execute SSH commands
@app.route('/run-command', methods=['POST'])
def run_command():
    client_ip = request.remote_addr  # Get client IP
    logging.info(f"Incoming request from IP: {client_ip}")

    if ip_manager.is_blocked(client_ip):
        logging.warning(f"Blocked request from IP: {client_ip} due to too many failed attempts.")
        return jsonify({'error': 'Your IP is temporarily blocked due to multiple failed attempts.'}), 403

    api_key = request.headers.get('X-Api-Key', type=str)
    data = request.json
    server_name = data['server_name']
    command_name = data['command_name']

    # Validate the API token
    token = api_manager.get_token(api_key)
    if not token:
        ip_manager.register_failed_attempt(client_ip)  # Register failed attempt
        logging.warning(f"Unauthorized access attempt with API key: {api_key} from IP: {client_ip}")
        return jsonify({'error': 'Unauthorized'}), 401

    # Check if the token has access to the server and command
    if not token.can_access(server_name, command_name):
        ip_manager.register_failed_attempt(client_ip)  # Register failed attempt
        logging.warning(f"Forbidden access attempt from IP: {client_ip} - server: {server_name}, command: {command_name}")
        return jsonify({'error': 'Forbidden: server or command not allowed'}), 403

    # Get the actual command and server credentials
    command = api_manager.get_command(command_name)
    if not command:
        logging.error(f"Command not found: {command_name}")
        return jsonify({'error': 'Command not found'}), 404

    host = api_manager.get_host(server_name)
    if not host:
        logging.error(f"SSH server not found: {server_name}")
        return jsonify({'error': 'SSH server not found'}), 500

    # Execute the command via SSH
    try:
        executor = SSHExecutor(host)
        output, error = executor.run_command(command)
        logging.info(f"Executed command: {command_name} on server: {server_name} - Output: {output.strip()}")
        return jsonify({'output': output, 'error': error}), 200
    except Exception as e:
        logging.error(f"Error executing command on server: {server_name} - Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    def handle_exit(signum, frame):
        print("\nReceived exit signal. Exiting...")
        sys.exit(0)
        
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)        
    # Load the config file
    with open('config.json') as f:
        config_data = json.load(f)
    # Initialize the classes
    api_manager = APIManager(config_data)
    ip_manager = IPManager()
    logger = logging.getLogger('waitress')
    logger.setLevel(logging.INFO)
    serve(app=app, host="0.0.0.0", port=5000)
    #app.run()
