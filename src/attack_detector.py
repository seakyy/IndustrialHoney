"""
Attack Detection System for IndustrialHoney
Detects and analyzes suspicious Modbus activities
"""

import logging
import time
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class AttackDetector:
    """
    Detects various attack patterns on industrial Modbus systems
    """

    def __init__(self):
        self.connection_history = defaultdict(deque)  # IP -> timestamps
        self.function_code_history = defaultdict(int)  # function_code -> count
        self.suspicious_writes = []
        self.attack_count = 0

        # Attack detection thresholds
        self.MAX_CONNECTIONS_PER_MINUTE = 10
        self.SUSPICIOUS_FUNCTION_CODES = [8, 17, 20, 21, 22, 23]  # Diagnostic/dangerous codes
        self.SUSPICIOUS_WRITE_VALUES = [0, 65535, 65000]  # Min/Max values often used in attacks

        logger.info("Attack Detection System initialized")

    def analyze_connection(self, client_ip: str) -> Dict[str, Any]:
        """
        Analyze new connection for suspicious patterns
        """
        current_time = time.time()

        # Add to connection history
        self.connection_history[client_ip].append(current_time)

        # Clean old entries (older than 1 minute)
        while (self.connection_history[client_ip] and
               current_time - self.connection_history[client_ip][0] > 60):
            self.connection_history[client_ip].popleft()

        # Check for rate limiting
        connection_count = len(self.connection_history[client_ip])
        is_rate_limited = connection_count > self.MAX_CONNECTIONS_PER_MINUTE

        if is_rate_limited:
            self.attack_count += 1
            logger.warning(f"RATE LIMIT EXCEEDED: {client_ip} ({connection_count} connections/min)")

        return {
            'client_ip': client_ip,
            'connection_count': connection_count,
            'is_suspicious': is_rate_limited,
            'attack_type': 'Rate Limiting' if is_rate_limited else None,
            'timestamp': datetime.now().isoformat()
        }

    def analyze_function_code(self, function_code: int, client_ip: str) -> Dict[str, Any]:
        """
        Analyze Modbus function codes for suspicious activity
        """
        self.function_code_history[function_code] += 1

        is_suspicious = function_code in self.SUSPICIOUS_FUNCTION_CODES

        if is_suspicious:
            self.attack_count += 1
            logger.warning(f"SUSPICIOUS FUNCTION CODE: {function_code} from {client_ip}")

        return {
            'function_code': function_code,
            'client_ip': client_ip,
            'is_suspicious': is_suspicious,
            'attack_type': f'Dangerous Function Code {function_code}' if is_suspicious else None,
            'description': self._get_function_code_description(function_code),
            'timestamp': datetime.now().isoformat()
        }

    def analyze_write_operation(self, register: int, value: int, client_ip: str) -> Dict[str, Any]:
        """
        Analyze write operations for suspicious values
        """
        is_suspicious = (
                value in self.SUSPICIOUS_WRITE_VALUES or
                value > 50000 or  # Unrealistically high values
                (register <= 6 and value > 30000)  # High values for critical sensors
        )

        if is_suspicious:
            self.attack_count += 1
            self.suspicious_writes.append({
                'register': register,
                'value': value,
                'client_ip': client_ip,
                'timestamp': datetime.now().isoformat()
            })
            logger.warning(f"SUSPICIOUS WRITE: Register {register} = {value} from {client_ip}")

        return {
            'register': register,
            'value': value,
            'client_ip': client_ip,
            'is_suspicious': is_suspicious,
            'attack_type': 'Malicious Write Operation' if is_suspicious else None,
            'timestamp': datetime.now().isoformat()
        }

    def _get_function_code_description(self, code: int) -> str:
        """Get human-readable description of Modbus function codes"""
        descriptions = {
            1: "Read Coils",
            2: "Read Discrete Inputs",
            3: "Read Holding Registers",
            4: "Read Input Registers",
            5: "Write Single Coil",
            6: "Write Single Register",
            15: "Write Multiple Coils",
            16: "Write Multiple Registers",
            8: "Diagnostics (SUSPICIOUS)",
            17: "Report Slave ID (RECON)",
            20: "Read File Record (SUSPICIOUS)",
            21: "Write File Record (DANGEROUS)",
            22: "Mask Write Register (DANGEROUS)",
            23: "Read/Write Multiple Registers (SUSPICIOUS)"
        }
        return descriptions.get(code, f"Unknown Function Code {code}")

    def get_attack_summary(self) -> Dict[str, Any]:
        """Get summary of all detected attacks"""
        return {
            'total_attacks': self.attack_count,
            'unique_attackers': len(self.connection_history),
            'suspicious_writes': len(self.suspicious_writes),
            'function_codes_used': dict(self.function_code_history),
            'last_updated': datetime.now().isoformat()
        }

    def generate_alert(self, attack_data: Dict[str, Any]) -> str:
        """Generate formatted alert message"""
        if not attack_data.get('is_suspicious'):
            return None

        alert = f"""
🚨 INDUSTRIAL SECURITY ALERT 

Time: {attack_data['timestamp']}
Source IP: {attack_data['client_ip']}
Attack Type: {attack_data['attack_type']}
Target: ABB Turbocharger Control Unit

Details: {attack_data.get('description', 'Suspicious activity detected')}

Risk Level: HIGH
Action Required: Immediate investigation recommended
        """

        return alert.strip()