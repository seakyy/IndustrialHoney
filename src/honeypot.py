"""
IndustrialHoney - Industrial Control Systems Honeypot
Main honeypot implementation for Modbus TCP simulation
"""
import os
import logging
import time
import random
import asyncio
from datetime import datetime
from pymodbus.datastore import ModbusServerContext, ModbusSequentialDataBlock, ModbusSlaveContext
from pymodbus.server.async_io import StartAsyncTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore.store import BaseModbusDataBlock
from alert_system import EmailAlerter
from dotenv import load_dotenv
from dashboard import integrate_with_honeypot
import threading

# Load environment variables
load_dotenv()

# Import our attack detector
from attack_detector import AttackDetector

# Setup logging
logging.basicConfig(
   level=logging.INFO,
   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HoneypotDataBlock(ModbusSequentialDataBlock):
   """
   Custom data block that logs all read/write operations
   """

   def __init__(self, address, values, attack_detector):
       super().__init__(address, values)
       self.attack_detector = attack_detector
       self.client_ip = "unknown"  # Will be set by server
       self.honeypot_instance = None  # Will be set by honeypot

   def setValues(self, address, values):
       """Override to detect write operations"""
       if hasattr(self, 'attack_detector') and self.attack_detector:
           for i, value in enumerate(values):
               register = address + i
               attack_data = self.attack_detector.analyze_write_operation(
                   register, value, self.client_ip
               )

               if attack_data['is_suspicious']:
                   alert = self.attack_detector.generate_alert(attack_data)
                   if alert:
                       logger.warning(f"SECURITY ALERT:\n{alert}")

                       # Send email alert (if configured)
                       if hasattr(self, 'honeypot_instance') and self.honeypot_instance:
                           self.honeypot_instance.email_alerter.send_security_alert(attack_data)

                           # Send to dashboard (NEW!)
                           if self.honeypot_instance.dashboard:
                               self.honeypot_instance.dashboard.add_attack(attack_data)

       # Log all write operations
       logger.info(f"WRITE: Client {self.client_ip} → Register {address} = {values}")
       return super().setValues(address, values)

   def getValues(self, address, count=1):
       """Override to detect read operations"""
       values = super().getValues(address, count)

       # Log all read operations
       logger.info(f"READ: Client {self.client_ip} → Register {address}-{address + count - 1} = {values}")

       # Update dashboard with sensor data (NEW!)
       if hasattr(self, 'honeypot_instance') and self.honeypot_instance and self.honeypot_instance.dashboard:
           if address == 1 and count >= 6:  # Reading all 6 sensors
               sensor_data = {
                   'turbine_speed': values[0] * 10,  # Scale back up
                   'boost_pressure': values[1],
                   'exhaust_temp': values[2],
                   'oil_pressure': values[3],
                   'fuel_flow': values[4],
                   'air_flow': values[5]
               }
               self.honeypot_instance.dashboard.update_sensor_data(sensor_data)

       return values


class TurbochargerHoneypot:
   """
   ABB Turbocharger simulation honeypot for detecting industrial cyberattacks
   """

   def __init__(self, port=502, dev_mode=False):
       self.port = 5020 if dev_mode else port
       self.dev_mode = dev_mode
       self.attack_count = 0
       self.connections = []

       # Initialize attack detector
       self.attack_detector = AttackDetector()

       # Initialize email alerter
       self.email_alerter = EmailAlerter()

       # Configure from environment variables
       sender_email = os.getenv('EMAIL_SENDER')
       sender_password = os.getenv('EMAIL_PASSWORD')
       recipient_email = os.getenv('EMAIL_RECIPIENT')

       if sender_email and sender_password and recipient_email:
           self.email_alerter.configure(sender_email, sender_password, recipient_email)
           logger.info("Email alerts enabled")
       else:
           logger.warning("Email credentials not configured - alerts disabled")

       # Turbocharger register mappings
       self.registers = {
           0x0001: "Turbine Speed (RPM)",
           0x0002: "Boost Pressure (kPa)",
           0x0003: "Exhaust Temperature (°C)",
           0x0004: "Oil Pressure (bar)",
           0x0005: "Fuel Flow Rate (kg/h)",
           0x0006: "Air Flow Rate (kg/s)"
       }

       # Dashboard integration
       self.dashboard = None
       self.dashboard_thread = None

       logger.info(f"Initializing Turbocharger Honeypot on port {self.port}")

   def start_dashboard(self, dashboard_port=5000):
       """Start the web dashboard in a separate thread"""

       def run_dashboard():
           from dashboard import start_dashboard_server, dashboard
           self.dashboard = dashboard
           start_dashboard_server(port=dashboard_port)

       self.dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
       self.dashboard_thread.start()
       logger.info(f"Dashboard started on http://localhost:{dashboard_port}")

   def generate_realistic_data(self):
       """Generate realistic turbocharger sensor data"""
       return {
           'turbine_speed': random.randint(15000, 25000),
           'boost_pressure': random.randint(150, 300),
           'exhaust_temp': random.randint(400, 650),
           'oil_pressure': random.randint(2, 5),
           'fuel_flow': random.randint(50, 200),
           'air_flow': random.randint(10, 50)
       }

   def setup_modbus_context(self):
       """Setup Modbus server context with attack detection"""
       # Generate realistic data
       data = self.generate_realistic_data()
       initial_values = [
           data['turbine_speed'] // 10,
           data['boost_pressure'],
           data['exhaust_temp'],
           data['oil_pressure'],
           data['fuel_flow'],
           data['air_flow']
       ] + [0] * 94  # Fill rest with zeros

       # Use our custom data block with attack detection
       holding_registers = HoneypotDataBlock(0, initial_values, self.attack_detector)
       input_registers = HoneypotDataBlock(0, [0] * 100, self.attack_detector)

       # Add reference to honeypot instance for email alerts
       holding_registers.honeypot_instance = self
       input_registers.honeypot_instance = self

       # Create slave context
       store = ModbusSlaveContext(
           di=ModbusSequentialDataBlock(0, [0] * 100),  # Discrete Inputs
           co=ModbusSequentialDataBlock(0, [0] * 100),  # Coils
           hr=holding_registers,  # Holding Registers (with detection)
           ir=input_registers  # Input Registers (with detection)
       )

       context = ModbusServerContext(slaves=store, single=True)
       return context

   def setup_device_identity(self):
       """Setup realistic ABB device identification"""
       identity = ModbusDeviceIdentification()
       identity.VendorName = 'ABB'
       identity.ProductCode = 'TPL-77K'
       identity.VendorUrl = 'https://new.abb.com/products/turbocharging'
       identity.ProductName = 'Turbocharger Control Unit'
       identity.ModelName = 'TPL-77K Industrial Honeypot'
       identity.MajorMinorRevision = '2.1.0'

       return identity

   def start_server(self):
       """Start the Modbus TCP honeypot server"""
       async def run_server():
           try:
               context = self.setup_modbus_context()
               identity = self.setup_device_identity()

               logger.info(f"Starting ABB Turbocharger Honeypot")
               logger.info(f"Listening on port {self.port}")
               logger.info(f"Ready to detect industrial cyberattacks")

               if self.dev_mode:
                   logger.info("Development Mode - Use port 5020 for testing")

               # Start async Modbus TCP server
               server_task = asyncio.create_task(
                   StartAsyncTcpServer(
                       context=context,
                       identity=identity,
                       address=("0.0.0.0", self.port)
                   )
               )

               await asyncio.sleep(0.1)

               logger.info("Honeypot server ready for connections!")
               logger.info("Attack detection system active")
               logger.info("Test with: python demo/test_client.py")
               logger.info("Press Ctrl+C to stop")

               await server_task

           except KeyboardInterrupt:
               logger.info("Honeypot stopped by user")
               # Print attack summary
               summary = self.attack_detector.get_attack_summary()
               logger.info(f"Attack Summary: {summary['total_attacks']} attacks detected")
               return
           except Exception as e:
               logger.error(f"Failed to start honeypot: {e}")

       try:
           asyncio.run(run_server())
       except KeyboardInterrupt:
           logger.info("Goodbye!")


def main():
    """Main entry point"""
    print("IndustrialHoney - ABB Turbocharger Honeypot")
    print("=" * 50)

    honeypot = TurbochargerHoneypot(dev_mode=True)

    # Start dashboard
    honeypot.start_dashboard(dashboard_port=5000)

    # Start honeypot (this will block)
    honeypot.start_server()


if __name__ == "__main__":
   main()