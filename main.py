class Packet:
    def __init__(self, src, dst, content):
        self._src = src
        self._dst = dst
        self._content = content 

    ################# Returns content of the packet #################
    def get_content(self):
        return self._content

    ################# Returns source IP of the packet #################
    def get_src(self):
        return self._src

    ################# Returns destination IP of the packet #################
    def get_dst(self):
        return self._dst

################################################################

class TrafficAnalyzer:
    # Stores the packets traffic
    def __init__(self):
        self.packets = []  # Fixed typo: should be self.packets

    # Adds packet to the traffic
    def add_packet(self, packet):
        self.packets.append(packet)  # Fixed typo: should be self.packets, not self.packet

    # Returns the traffic summary based on the packets  
    def get_traffic_summary(self):
        return f"Total packets: {len(self.packets)}"

################################################################

# Placeholder for detection
class Detection:
    def detect(self, packet):
        raise NotImplementedError("Subclass should be implemented this way.")

################################################################

# Initializes SignatureDetection with known signatures 
class SignatureDetection(Detection):
    def __init__(self, signatures):
        self.signatures = signatures

    # Detects if the packet contains signatures 
    def detect(self, packet):
        content = packet.get_content()  # Fixed typo: should be get_content() instead of _get_content()
        for signature in self.signatures:
            if signature in content:
                return True 
        return False 

################################################################

# Detects based on packet characteristics
class AnomalyDetection(Detection):
    def detect(self, packet):
        if len(packet.get_content()) > 1000: 
            return True 
        return False 

################################################################

# Sends the alert message 
class AlertSystem:
    def alert(self, message):
        print(f"ALERT: {message}")

################################################################

# Sets IDS with the necessary components 
class IntrusionDetectionSystem:
    def __init__(self, signatures):
        self.traffic_analyzer = TrafficAnalyzer()
        self.signature_detector = SignatureDetection(signatures)
        self.anomaly_detector = AnomalyDetection()
        self.alert_system = AlertSystem()

    # Process the packet 
    def process_packet(self, packet):
        self.traffic_analyzer.add_packet(packet)
        
        if self.signature_detector.detect(packet):
            self.alert_system.alert("Signature-based Intrusion Detected!")

        if self.anomaly_detector.detect(packet):
            self.alert_system.alert("Anomaly-based Intrusion Detected!")

    def get_traffic_summary(self):
        return self.traffic_analyzer.get_traffic_summary()

################################################################

# Main function to run the IDS
if __name__ == "__main__":
    signatures = ["malware", "phishing"] 

    # Initialize the IDS with known signatures
    ids = IntrusionDetectionSystem(signatures)
    
    # Simulate network traffic with some packets
    packets = [
        Packet("192.168.1.1", "192.168.1.2", "Normal traffic data"),
        Packet("192.168.1.2", "192.168.1.3", "Potential Malware Detection"),
        Packet("192.168.1.3", "192.168.1.4", "Large payload unusual content" * 50)    
    ]

    # Process each packet through the IDS
    for packet in packets:
        ids.process_packet(packet)

    # Print a summary of the traffic
    print(ids.get_traffic_summary())
