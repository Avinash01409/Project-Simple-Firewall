# Define the Settings class using the Singleton pattern
class Settings:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
            # Initialize default settings here
            cls._instance.default_policy = "allow"
        return cls._instance

    def get_default_policy(self):
        return self.default_policy

# Define the FirewallStrategy abstract base class using the Strategy pattern
from abc import ABC, abstractmethod

class FirewallStrategy(ABC):
    @abstractmethod
    def filter(self, packet: dict) -> bool:
        pass

# Implement the IPFilter class
class IPFilter(FirewallStrategy):
    def __init__(self):
        self.whitelist = set()
        self.blacklist = set()

    def add_to_whitelist(self, ip):
        self.whitelist.add(ip)

    def add_to_blacklist(self, ip):
        self.blacklist.add(ip)

    def filter(self, packet: dict) -> bool:
        ip = packet.get("ip")
        if ip in self.blacklist:
            return False
        if self.whitelist and ip not in self.whitelist:
            return False
        return True

# Implement the PortFilter class
class PortFilter(FirewallStrategy):
    def __init__(self):
        self.allowed_ports = set()

    def allow_port(self, port):
        self.allowed_ports.add(port)

    def filter(self, packet: dict) -> bool:
        port = packet.get("port")
        if self.allowed_ports and port not in self.allowed_ports:
            return False
        return True

# Implement the ProtocolFilter class
class ProtocolFilter(FirewallStrategy):
    def __init__(self):
        self.allowed_protocols = set()

    def allow_protocol(self, protocol):
        self.allowed_protocols.add(protocol)

    def filter(self, packet: dict) -> bool:
        protocol = packet.get("protocol")
        if self.allowed_protocols and protocol not in self.allowed_protocols:
            return False
        return True

# Implement the StrategyFactory class using the Factory pattern
class StrategyFactory:
    @staticmethod
    def get_strategy(strategy_type: str):
        if strategy_type == "ip_filter":
            return IPFilter()
        elif strategy_type == "port_filter":
            return PortFilter()
        elif strategy_type == "protocol_filter":
            return ProtocolFilter()
        else:
            raise ValueError(f"Unknown strategy type: {strategy_type}")

# Implement the main script to use the strategies for filtering network traffic
def main():
    import re

    def is_valid_ip(ip):
        # Simple regex for basic IP validation
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return pattern.match(ip) is not None

    settings = Settings()
    default_policy = settings.get_default_policy()

    ip_filter = StrategyFactory.get_strategy("ip_filter")
    port_filter = StrategyFactory.get_strategy("port_filter")
    protocol_filter = StrategyFactory.get_strategy("protocol_filter")

    # Add custom IP filter rules
    ip_filter.add_to_whitelist("192.168.1.1")
    ip_filter.add_to_blacklist("10.0.0.1")

    # Add custom port filter rules
    port_filter.allow_port(80)
    port_filter.allow_port(443)

    # Add custom protocol filter rules
    protocol_filter.allow_protocol("TCP")
    protocol_filter.allow_protocol("UDP")

    allowed_protocols = {"TCP", "UDP"}

    print("Advanced Firewall is running...")
    print("Enter packet details in the format 'ip, port, protocol' (e.g., '192.168.1.1, 80, TCP')")
    while True:
        packet_input = input("Enter packet details (or type 'exit' to quit): ")
        if packet_input.lower() == 'exit':
            break
        try:
            errors = []
            # Split the input and convert to dictionary format
            parts = packet_input.split(', ')
            if len(parts) != 3:
                errors.append("Invalid packet format. Please enter the details in the format 'ip, port, protocol' (e.g., '192.168.1.1, 80, TCP').")
            else:
                ip, port, protocol = parts

                if not is_valid_ip(ip):
                    errors.append("Invalid IP format. Please enter a valid IP address (e.g., 192.168.1.1).")

                try:
                    port = int(port)  # Convert port to integer
                except ValueError:
                    errors.append("Invalid port number. Please enter a numeric port value.")

                if protocol not in allowed_protocols:
                    errors.append(f"Invalid protocol. Please enter a valid protocol (e.g., {', '.join(allowed_protocols)}).")

            if errors:
                for error in errors:
                    print(error)
                continue
            
            packet = {
                "ip": ip,
                "port": port,
                "protocol": protocol
            }

            if ip_filter.filter(packet) and port_filter.filter(packet) and protocol_filter.filter(packet):
                print("Packet allowed")
            else:
                print("Packet denied")
        except Exception as e:
            print("An unexpected error occurred:", e)

if __name__ == "__main__":
    main()
