"""
Simple Modbus client to test the honeypot
"""

from pymodbus.client import ModbusTcpClient
import time


def test_honeypot():
    print("Testing IndustrialHoney Honeypot")
    print("=" * 40)

    # Connect to honeypot
    client = ModbusTcpClient('localhost', port=5020)

    try:
        if client.connect():
            print("Connected to honeypot!")

            # Read turbocharger data
            print("\nReading turbocharger sensor data:")
            result = client.read_holding_registers(1, 6, unit=1)

            if result.isError():
                print("Error reading registers")
            else:
                sensors = ["Turbine Speed", "Boost Pressure", "Exhaust Temp",
                           "Oil Pressure", "Fuel Flow", "Air Flow"]

                for i, value in enumerate(result.registers):
                    print(f"   {sensors[i]}: {value}")

            # Try suspicious write (this should be detected!)
            print("\nAttempting suspicious write operation...")
            client.write_register(1, 65000, unit=1)  # Maximum Modbus value - suspicious!

            client.close()
            print("Test completed!")

        else:
            print("Failed to connect to honeypot")

    except Exception as e:
        print(f"Test failed: {e}")


if __name__ == "__main__":
    test_honeypot()