"""
Real-time Web Dashboard for IndustrialHoney
Live attack monitoring and visualization
"""

import json
import time
from datetime import datetime
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import threading
import logging

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='../web/templates', static_folder='../web/static')
app.config['SECRET_KEY'] = 'industrialhoney-dashboard-secret'
socketio = SocketIO(app, cors_allowed_origins="*")


class DashboardManager:
    """
    Manages real-time dashboard data and WebSocket connections
    """

    def __init__(self):
        self.attacks = []
        self.sensor_data = {}
        self.stats = {
            'total_attacks': 0,
            'unique_ips': set(),
            'attack_types': {},
            'last_attack': None
        }

        logger.info("Dashboard Manager initialized")

    def add_attack(self, attack_data):
        """Add new attack to dashboard"""
        self.attacks.append(attack_data)
        self.stats['total_attacks'] += 1
        self.stats['unique_ips'].add(attack_data.get('client_ip', 'unknown'))

        attack_type = attack_data.get('attack_type', 'Unknown')
        self.stats['attack_types'][attack_type] = self.stats['attack_types'].get(attack_type, 0) + 1
        self.stats['last_attack'] = datetime.now().isoformat()

        # Emit to all connected clients
        socketio.emit('new_attack', attack_data)
        logger.info(f"Attack added to dashboard: {attack_type}")

    def update_sensor_data(self, sensor_data):
        """Update current sensor readings"""
        self.sensor_data = sensor_data
        socketio.emit('sensor_update', sensor_data)

    def get_dashboard_data(self):
        """Get complete dashboard data"""
        return {
            'attacks': self.attacks[-50:],  # Last 50 attacks
            'sensor_data': self.sensor_data,
            'stats': {
                'total_attacks': self.stats['total_attacks'],
                'unique_ips': len(self.stats['unique_ips']),
                'attack_types': self.stats['attack_types'],
                'last_attack': self.stats['last_attack']
            }
        }


# Global dashboard manager
dashboard = DashboardManager()


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/dashboard-data')
def get_dashboard_data():
    """API endpoint for dashboard data"""
    return jsonify(dashboard.get_dashboard_data())


@app.route('/api/demo/trigger-attack')
def demo_attack():
    """Demo endpoint to trigger fake attack"""
    fake_attack = {
        'timestamp': datetime.now().isoformat(),
        'client_ip': '192.168.1.100',
        'attack_type': 'Demo Attack',
        'register': 1,
        'value': 99999,
        'is_suspicious': True
    }
    dashboard.add_attack(fake_attack)
    return jsonify({'status': 'demo_attack_triggered'})


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Dashboard client connected")
    emit('dashboard_data', dashboard.get_dashboard_data())


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Dashboard client disconnected")


def start_dashboard_server(host='0.0.0.0', port=5000):
    """Start the dashboard server"""
    logger.info(f"Starting dashboard server on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)


# Global reference for honeypot integration
def integrate_with_honeypot(honeypot_instance):
    """Integrate dashboard with honeypot"""
    global dashboard
    honeypot_instance.dashboard = dashboard
    logger.info("Dashboard integrated with honeypot")


if __name__ == "__main__":
    start_dashboard_server()