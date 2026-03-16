"""
Network Intelligence Engine
Advanced root cause analysis and suspicious behavior detection for Network Stability Monitor Pro
"""

import re
import json
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta


@dataclass
class RootCauseProbability:
    router_issue: float = 0.0
    isp_issue: float = 0.0
    dns_issue: float = 0.0
    local_adapter_issue: float = 0.0
    possible_malicious_activity: float = 0.0
    unknown: float = 0.0
    
    def normalize(self):
        total = sum([self.router_issue, self.isp_issue, self.dns_issue, 
                    self.local_adapter_issue, self.possible_malicious_activity, self.unknown])
        if total > 0:
            self.router_issue /= total
            self.isp_issue /= total
            self.dns_issue /= total
            self.local_adapter_issue /= total
            self.possible_malicious_activity /= total
            self.unknown /= total


@dataclass
class SuspiciousIndicators:
    gateway_ip_changes: int = 0
    dns_server_changes: int = 0
    subnet_changes: int = 0
    high_dns_failures: bool = False
    frequent_disconnections: bool = False
    private_to_public_shifts: int = 0
    rapid_flapping: bool = False
    unexpected_config_changes: int = 0
    
    def suspicion_level(self) -> str:
        score = sum([
            self.gateway_ip_changes * 2,
            self.dns_server_changes * 1.5,
            self.subnet_changes * 3,
            2 if self.high_dns_failures else 0,
            1.5 if self.frequent_disconnections else 0,
            self.private_to_public_shifts * 4,
            2 if self.rapid_flapping else 0,
            self.unexpected_config_changes * 1
        ])
        
        if score >= 8:
            return "HIGH"
        elif score >= 4:
            return "MEDIUM"
        elif score >= 1:
            return "LOW"
        return "NONE"


@dataclass
class AnomalyFlags:
    gateway_unexpected_change: bool = False
    dns_unexpected_change: bool = False
    subnet_change: bool = False
    high_latency_without_loss: bool = False
    rapid_state_changes: bool = False
    dns_failures_with_connectivity: bool = False
    configuration_drift: bool = False
    unusual_packet_loss_pattern: bool = False


class NetworkIntelligenceEngine:
    def __init__(self):
        self.baseline_gateway = ""
        self.baseline_dns = []
        self.baseline_subnet = ""
        
        # Tracking for anomaly detection
        self.gateway_history: List[Tuple[float, str]] = []
        self.dns_history: List[Tuple[float, List[str]]] = []
        self.subnet_history: List[Tuple[float, str]] = []
        self.state_history: List[Tuple[float, str]] = []
        
        # Time windows for analysis
        self.config_change_window = 300  # 5 minutes
        self.flap_detection_window = 120  # 2 minutes
        self.analysis_window = 1800  # 30 minutes
        
    def update_baseline(self, gateway: str, dns_servers: List[str], local_ip: str):
        """Update baseline configuration"""
        self.baseline_gateway = gateway
        self.baseline_dns = dns_servers.copy()
        self.baseline_subnet = self._extract_subnet(local_ip)
    
    def _extract_subnet(self, ip: str) -> str:
        """Extract subnet from IP address"""
        if not ip or '.' not in ip:
            return ""
        parts = ip.split('.')
        if len(parts) >= 3:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ""
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        if not ip:
            return False
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first, second = int(parts[0]), int(parts[1])
            return (first == 10) or (first == 192 and second == 168) or (first == 172 and 16 <= second <= 31)
        except ValueError:
            return False
    
    def track_configuration(self, gateway: str, dns_servers: List[str], local_ip: str, timestamp: float):
        """Track configuration changes over time"""
        current_time = timestamp
        
        # Track gateway
        if gateway:
            self.gateway_history.append((current_time, gateway))
            self.gateway_history = [(t, g) for t, g in self.gateway_history 
                                  if current_time - t <= self.analysis_window]
        
        # Track DNS
        if dns_servers:
            self.dns_history.append((current_time, dns_servers.copy()))
            self.dns_history = [(t, d) for t, d in self.dns_history 
                              if current_time - t <= self.analysis_window]
        
        # Track subnet
        current_subnet = self._extract_subnet(local_ip)
        if current_subnet:
            self.subnet_history.append((current_time, current_subnet))
            self.subnet_history = [(t, s) for t, s in self.subnet_history 
                                 if current_time - t <= self.analysis_window]
    
    def track_state_changes(self, status: str, timestamp: float):
        """Track network state changes for flapping detection"""
        self.state_history.append((timestamp, status))
        self.state_history = [(t, s) for t, s in self.state_history 
                            if timestamp - t <= self.flap_detection_window]
    
    def detect_suspicious_indicators(self, current_time: float) -> SuspiciousIndicators:
        """Detect suspicious behavior patterns"""
        indicators = SuspiciousIndicators()
        
        # Gateway IP changes
        if len(self.gateway_history) > 1:
            unique_gateways = set(g for _, g in self.gateway_history)
            indicators.gateway_ip_changes = len(unique_gateways) - 1
        
        # DNS server changes
        if len(self.dns_history) > 1:
            unique_dns_configs = set(tuple(sorted(d)) for _, d in self.dns_history)
            indicators.dns_server_changes = len(unique_dns_configs) - 1
        
        # Subnet changes
        if len(self.subnet_history) > 1:
            unique_subnets = set(s for _, s in self.subnet_history)
            indicators.subnet_changes = len(unique_subnets) - 1
        
        # Frequent disconnections (rapid state changes)
        if len(self.state_history) > 5:
            transitions = 0
            prev_status = None
            for _, status in sorted(self.state_history):
                if prev_status and status != prev_status:
                    transitions += 1
                prev_status = status
            indicators.frequent_disconnections = transitions >= 8
        
        # Rapid flapping detection
        if len(self.state_history) >= 4:
            recent_states = [status for _, status in sorted(self.state_history[-10:])]
            ok_count = recent_states.count("OK")
            total_count = len(recent_states)
            if ok_count < total_count * 0.3:  # Less than 30% OK in recent samples
                indicators.rapid_flapping = True
        
        return indicators
    
    def detect_anomalies(self, sample_data: Dict, rolling_stats: Dict) -> AnomalyFlags:
        """Detect various network anomalies"""
        anomalies = AnomalyFlags()
        
        # Gateway unexpected change
        if (self.baseline_gateway and 
            sample_data.get('gateway_ip') and 
            sample_data['gateway_ip'] != self.baseline_gateway):
            anomalies.gateway_unexpected_change = True
        
        # DNS unexpected change
        if (self.baseline_dns and 
            sample_data.get('dns_servers') and 
            set(sample_data['dns_servers']) != set(self.baseline_dns)):
            anomalies.dns_unexpected_change = True
        
        # High latency without packet loss
        max_latency = rolling_stats.get('max_latency_ms', 0)
        packet_loss = rolling_stats.get('packet_loss_percent', 0)
        if max_latency > 200 and packet_loss < 5:
            anomalies.high_latency_without_loss = True
        
        # DNS failures with connectivity
        if (sample_data.get('dns_state') == 'FAIL' and 
            sample_data.get('inet_ok', False)):
            anomalies.dns_failures_with_connectivity = True
        
        # Configuration drift
        indicators = self.detect_suspicious_indicators(time.time())
        if indicators.suspicion_level() in ["MEDIUM", "HIGH"]:
            anomalies.configuration_drift = True
        
        return anomalies
    
    def calculate_root_cause_probability(self, 
                                       sample_data: Dict,
                                       rolling_stats: Dict,
                                       anomalies: AnomalyFlags) -> RootCauseProbability:
        """Calculate probability distribution for root causes"""
        probs = RootCauseProbability()
        
        # Extract key metrics
        gw_ok = sample_data.get('gw_ok', True)
        inet_ok = sample_data.get('inet_ok', True)
        inet2_ok = sample_data.get('inet2_ok', True)
        dns_state = sample_data.get('dns_state', 'OK')
        local_ip = sample_data.get('local_ip', '')
        wifi_state = sample_data.get('wifi_state', '').lower()
        
        packet_loss = rolling_stats.get('packet_loss_percent', 0)
        max_latency = rolling_stats.get('max_latency_ms', 0)
        gw_loss = rolling_stats.get('gw_loss_percent', 0)
        
        # Router issue indicators
        if not gw_ok and not inet_ok and not inet2_ok:
            probs.router_issue += 0.7
        if gw_loss > 50:
            probs.router_issue += 0.3
        if anomalies.gateway_unexpected_change:
            probs.router_issue += 0.4
        if 'disconnected' in wifi_state or not local_ip:
            probs.router_issue += 0.6
        
        # ISP issue indicators
        if gw_ok and (not inet_ok and not inet2_ok):
            probs.isp_issue += 0.8
        if packet_loss > 30 and gw_loss < 10:
            probs.isp_issue += 0.4
        if max_latency > 300 and gw_loss < 5:
            probs.isp_issue += 0.3
        
        # DNS issue indicators
        if (inet_ok or inet2_ok) and dns_state == 'FAIL':
            probs.dns_issue += 0.9
        if (inet_ok or inet2_ok) and dns_state == 'SLOW':
            probs.dns_issue += 0.6
        if anomalies.dns_failures_with_connectivity:
            probs.dns_issue += 0.7
        if anomalies.dns_unexpected_change:
            probs.dns_issue += 0.3
        
        # Local adapter issue indicators
        if not local_ip and 'connected' in wifi_state:
            probs.local_adapter_issue += 0.8
        if 'disconnected' in wifi_state:
            probs.local_adapter_issue += 0.7
        if anomalies.subnet_change:
            probs.local_adapter_issue += 0.4
        
        # Malicious activity indicators
        if anomalies.gateway_unexpected_change:
            probs.possible_malicious_activity += 0.3
        if anomalies.dns_unexpected_change:
            probs.possible_malicious_activity += 0.2
        if anomalies.configuration_drift:
            probs.possible_malicious_activity += 0.4
        if anomalies.rapid_state_changes:
            probs.possible_malicious_activity += 0.2
        
        # Normalize probabilities
        probs.normalize()
        
        return probs
    
    def generate_explanation(self, 
                           sample_data: Dict,
                           rolling_stats: Dict,
                           anomalies: AnomalyFlags,
                           root_cause: RootCauseProbability) -> str:
        """Generate human-readable explanation"""
        
        # Extract key metrics for explanation
        gw_ok = sample_data.get('gw_ok', True)
        inet_ok = sample_data.get('inet_ok', True)
        inet2_ok = sample_data.get('inet2_ok', True)
        dns_state = sample_data.get('dns_state', 'OK')
        gw_rtt = sample_data.get('gw_rtt')
        inet_rtt = sample_data.get('inet_rtt')
        
        packet_loss = rolling_stats.get('packet_loss_percent', 0)
        max_latency = rolling_stats.get('max_latency_ms', 0)
        
        explanation_parts = []
        
        # Gateway analysis
        if gw_ok and gw_rtt is not None:
            explanation_parts.append(f"Gateway reachable with {gw_rtt:.0f} ms latency")
        elif not gw_ok:
            explanation_parts.append("Gateway unreachable")
        
        # Internet connectivity analysis
        inet_count = sum([inet_ok, inet2_ok])
        if inet_count == 2:
            explanation_parts.append("both internet targets reachable")
        elif inet_count == 1:
            explanation_parts.append("one internet target reachable")
        else:
            explanation_parts.append("both internet targets failed")
        
        # DNS analysis
        if dns_state == 'OK':
            explanation_parts.append("DNS functioning normally")
        elif dns_state == 'SLOW':
            explanation_parts.append("DNS experiencing timeouts")
        else:
            explanation_parts.append("DNS failing")
        
        # Performance analysis
        if packet_loss > 25:
            explanation_parts.append(f"high packet loss ({packet_loss:.0f}%)")
        elif max_latency > 200:
            explanation_parts.append(f"high latency (max {max_latency:.0f} ms)")
        
        # Anomaly explanations
        if anomalies.gateway_unexpected_change:
            explanation_parts.append("gateway IP changed from baseline")
        if anomalies.dns_unexpected_change:
            explanation_parts.append("DNS servers changed from baseline")
        if anomalies.configuration_drift:
            explanation_parts.append("configuration changes detected")
        
        # Determine most likely cause
        max_prob = max([root_cause.router_issue, root_cause.isp_issue, root_cause.dns_issue,
                       root_cause.local_adapter_issue, root_cause.possible_malicious_activity])
        
        cause_map = {
            root_cause.router_issue: "router issue",
            root_cause.isp_issue: "ISP issue", 
            root_cause.dns_issue: "DNS issue",
            root_cause.local_adapter_issue: "local adapter issue",
            root_cause.possible_malicious_activity: "possible malicious activity"
        }
        
        most_likely = "unknown"
        for prob_val, cause_name in cause_map.items():
            if prob_val == max_prob and prob_val > 0.3:
                most_likely = cause_name
                break
        
        # Build final explanation
        explanation = ". ".join(explanation_parts) + "."
        
        if most_likely != "unknown":
            explanation += f" Most probable cause: {most_likely} ({max_prob:.2f} probability)."
        else:
            explanation += " Cause unclear, requires further investigation."
        
        return explanation
    
    def generate_ai_export(self, 
                          current_sample: Dict,
                          rolling_stats: Dict,
                          incidents: List[Dict],
                          anomalies: AnomalyFlags,
                          root_cause: RootCauseProbability) -> Dict:
        """Generate lightweight AI-friendly export"""
        
        # Calculate last 5 minutes statistics
        five_min_ago = time.time() - 300
        recent_incidents = [inc for inc in incidents 
                          if self._parse_timestamp(inc.get('start_time', '')) and 
                           self._parse_timestamp(inc.get('start_time', '')) > five_min_ago]
        
        export = {
            "system_snapshot": {
                "local_ip": current_sample.get('local_ip', ''),
                "gateway": current_sample.get('gateway_ip', ''),
                "dns_servers": current_sample.get('dns_servers', []),
                "wifi_signal": current_sample.get('wifi_signal', ''),
                "interface": current_sample.get('iface', '')
            },
            "last_5min_statistics": {
                "packet_loss_percent": {
                    "gateway": rolling_stats.get('gw_loss_percent', 0),
                    "internet1": rolling_stats.get('inet1_loss_percent', 0),
                    "internet2": rolling_stats.get('inet2_loss_percent', 0)
                },
                "max_latency_ms": {
                    "gateway": rolling_stats.get('gw_max_latency', 0),
                    "internet1": rolling_stats.get('inet1_max_latency', 0),
                    "internet2": rolling_stats.get('inet2_max_latency', 0)
                },
                "dns_fail_rate": rolling_stats.get('dns_fail_rate', 0),
                "state_transitions": rolling_stats.get('state_transitions', 0)
            },
            "current_status": current_sample.get('status', ''),
            "current_reason": current_sample.get('reason', ''),
            "incidents_last_30min": [
                {
                    "start": inc.get('start_time', ''),
                    "duration": inc.get('duration', ''),
                    "category": inc.get('category', ''),
                    "severity": inc.get('severity', '')
                } for inc in recent_incidents[:10]
            ],
            "anomaly_flags": {
                "gateway_change": anomalies.gateway_unexpected_change,
                "dns_change": anomalies.dns_unexpected_change,
                "high_latency_no_loss": anomalies.high_latency_without_loss,
                "dns_fail_with_connection": anomalies.dns_failures_with_connectivity,
                "config_drift": anomalies.configuration_drift
            },
            "root_cause_probability": asdict(root_cause),
            "suspicion_level": self.detect_suspicious_indicators(time.time()).suspicion_level()
        }
        
        return export
    
    def _parse_timestamp(self, ts_str: str) -> float:
        """Parse timestamp string to unix timestamp"""
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            return dt.timestamp()
        except Exception:
            return 0.0
