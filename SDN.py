#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.node import CPULimitedHost, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import pandas as pd
import numpy as np
from collections import defaultdict
import time
from datetime import datetime
import threading
import signal
import sys
import subprocess
import os

class FlowStats:
    def __init__(self):
        self.reset_stats()

    def reset_stats(self):
        self.start_time = time.time()
        self.last_time = self.start_time
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_pkt_lens = []
        self.bwd_pkt_lens = []
        self.fwd_iat = []
        self.bwd_iat = []
        self.active_times = []
        self.idle_times = []
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        self.cwe_flags = 0
        self.ece_flags = 0
        self.syn_flags = 0
        self.fin_flags = 0
        self.rst_flags = 0
        self.ack_flags = 0
        self.init_fwd_win_bytes = 0
        self.init_bwd_win_bytes = 0
        self.last_active = self.start_time

class FlowMonitor:
    def __init__(self, net):
        self.net = net
        self.flows = defaultdict(FlowStats)
        self.running = True
        self.lock = threading.Lock()
        self.ai_ready_data = []

    # Add this method to the FlowMonitor class after update_ai_data method:

    def print_stats_realtime(self):
        """Print detailed statistics in real-time"""
        os.system('clear')
        print("\033[2J\033[H")  # Clear screen and move cursor to top
        print("=== Detailed Flow Statistics ===")
        print(f"Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        with self.lock:
            for flow_key, stats in self.flows.items():
                print("\n" + "="*100)
                print(f"Flow: {flow_key}")
                print("-"*100)
                
                current_time = time.time()
                duration = current_time - stats.start_time
                if duration == 0:
                    continue

                # Calculate all required metrics
                fwd_pkts_s = stats.fwd_pkts / duration if duration > 0 else 0
                bwd_pkts_s = stats.bwd_pkts / duration if duration > 0 else 0
                flow_bytes_s = (stats.fwd_bytes + stats.bwd_bytes) / duration
                flow_pkts_s = (stats.fwd_pkts + stats.bwd_pkts) / duration
                
                fwd_pkt_lens = stats.fwd_pkt_lens or [0]
                bwd_pkt_lens = stats.bwd_pkt_lens or [0]
                all_pkt_lens = fwd_pkt_lens + bwd_pkt_lens
                
                fwd_iat = stats.fwd_iat or [0]
                bwd_iat = stats.bwd_iat or [0]
                flow_iat = sorted(fwd_iat + bwd_iat)
                
                active_times = stats.active_times or [0]
                idle_times = stats.idle_times or [0]

                # Format and display metrics in columns
                metrics = {
                    "Basic Flow Information": {
                        "Source IP": flow_key.split('-')[0].split(':')[0],
                        "Destination IP": flow_key.split('-')[1].split(':')[0],
                        "Source Port": flow_key.split('-')[0].split(':')[1],
                        "Destination Port": flow_key.split('-')[1].split(':')[1],
                        "Timestamp": datetime.fromtimestamp(stats.start_time).strftime('%Y-%m-%d %H:%M:%S')
                    },
                    "Packet Statistics": {
                        "Forward Packets": stats.fwd_pkts,
                        "Backward Packets": stats.bwd_pkts,
                        "Forward Bytes": stats.fwd_bytes,
                        "Backward Bytes": stats.bwd_bytes,
                        "Fwd Packets/s": f"{fwd_pkts_s:.2f}",
                        "Bwd Packets/s": f"{bwd_pkts_s:.2f}",
                        "Flow Bytes/s": f"{flow_bytes_s:.2f}",
                        "Flow Packets/s": f"{flow_pkts_s:.2f}"
                    },
                    "Packet Length Statistics": {
                        "Fwd Seg Size Avg": f"{np.mean(fwd_pkt_lens):.2f}",
                        "Pkt Len Variance": f"{np.var(all_pkt_lens) if len(all_pkt_lens) > 1 else 0:.2f}",
                        "Bwd Pkt Len Std": f"{np.std(bwd_pkt_lens) if len(bwd_pkt_lens) > 1 else 0:.2f}",
                        "Total Fwd Packet Length": sum(fwd_pkt_lens)
                    },
                    "Timing Statistics": {
                        "Flow IAT Mean": f"{np.mean(flow_iat):.2f}",
                        "Bwd IAT Min": f"{min(bwd_iat) if bwd_iat else 0:.2f}",
                        "Bwd IAT Total": f"{sum(bwd_iat):.2f}",
                        "Active Mean": f"{np.mean(active_times):.2f}",
                        "Idle Mean": f"{np.mean(idle_times):.2f}"
                    },
                    "TCP Flags": {
                        "SYN Flags": stats.syn_flags,
                        "ACK Flags": stats.ack_flags,
                        "FIN Flags": stats.fin_flags,
                        "RST Flags": stats.rst_flags,
                        "PSH Flags (Fwd/Bwd)": f"{stats.fwd_psh_flags}/{stats.bwd_psh_flags}",
                        "URG Flags (Fwd/Bwd)": f"{stats.fwd_urg_flags}/{stats.bwd_urg_flags}",
                        "CWE Flags": stats.cwe_flags,
                        "ECE Flags": stats.ece_flags
                    },
                    "Window Statistics": {
                        "Init Fwd Win Bytes": stats.init_fwd_win_bytes,
                        "Init Bwd Win Bytes": stats.init_bwd_win_bytes
                    }
                }

                # Print metrics in a structured format
                for section, values in metrics.items():
                    print(f"\n{section}:")
                    print("-" * 50)
                    max_key_length = max(len(k) for k in values.keys())
                    for key, value in values.items():
                        print(f"{key:<{max_key_length + 2}}: {value}")

        sys.stdout.flush() 
    def get_ai_features(self, flow_key, stats):
        current_time = time.time()
        duration = current_time - stats.start_time

        if duration == 0:
            return None

        # Calculate basic metrics
        fwd_pkts_s = stats.fwd_pkts / duration
        bwd_pkts_s = stats.bwd_pkts / duration
        flow_bytes_s = (stats.fwd_bytes + stats.bwd_bytes) / duration
        flow_pkts_s = (stats.fwd_pkts + stats.bwd_pkts) / duration

        # Calculate packet length statistics
        fwd_pkt_lens = stats.fwd_pkt_lens or [0]
        bwd_pkt_lens = stats.bwd_pkt_lens or [0]
        all_pkt_lens = fwd_pkt_lens + bwd_pkt_lens

        # Calculate IAT statistics
        fwd_iat = stats.fwd_iat or [0]
        bwd_iat = stats.bwd_iat or [0]
        flow_iat = sorted(fwd_iat + bwd_iat)

        # Active/Idle times
        active_times = stats.active_times or [0]
        idle_times = stats.idle_times or [0]

        features = {
            'Fwd Seg Size Avg': np.mean(fwd_pkt_lens),
            'CWE Flag Count': stats.cwe_flags,
            'Fwd Pkts/s': fwd_pkts_s,
            'Bwd Pkts/s': bwd_pkts_s,
            'Dst Port': int(flow_key.split('-')[1].split(':')[1]),
            'Fwd URG Flags': stats.fwd_urg_flags,
            'Flow ID': flow_key,
            'Fwd Act Data Pkts': stats.fwd_pkts,
            'Pkt Len Var': np.var(all_pkt_lens) if len(all_pkt_lens) > 1 else 0,
            'Flow IAT Mean': np.mean(flow_iat),
            'Bwd IAT Min': min(bwd_iat) if bwd_iat else 0,
            'ACK Flag Cnt': stats.ack_flags,
            'Bwd Pkt Len Std': np.std(bwd_pkt_lens) if len(bwd_pkt_lens) > 1 else 0,
            'TotLen Fwd Pkts': sum(fwd_pkt_lens),
            'Bwd IAT Tot': sum(bwd_iat),
            'Timestamp': datetime.fromtimestamp(stats.start_time).strftime('%Y-%m-%d %H:%M:%S'),
            'Active Mean': np.mean(active_times),
            'Idle Mean': np.mean(idle_times),
            'SYN Flag Cnt': stats.syn_flags,
            'Flow Byts/s': flow_bytes_s,
            'Flow Pkts/s': flow_pkts_s,
            'Init Fwd Win Byts': stats.init_fwd_win_bytes,
            'Init Bwd Win Byts': stats.init_bwd_win_bytes,
            'Fwd PSH Flags': stats.fwd_psh_flags,
            'Bwd PSH Flags': stats.bwd_psh_flags,
            'Fwd URG Flags': stats.fwd_urg_flags,
            'Bwd URG Flags': stats.bwd_urg_flags,
            'FIN Flag Cnt': stats.fin_flags,
            'RST Flag Cnt': stats.rst_flags,
            'ECE Flag Cnt': stats.ece_flags,
            'Src Port': int(flow_key.split('-')[0].split(':')[1]),
            'Src IP': flow_key.split('-')[0].split(':')[0],
            'Dst IP': flow_key.split('-')[1].split(':')[0],
        }

        return features

    def collect_flow_stats(self):
        while self.running:
            try:
                for switch in self.net.switches:
                    output = subprocess.check_output(
                        ['ovs-ofctl', 'dump-flows', switch.name],
                        universal_newlines=True
                    )
                    
                    current_time = time.time()
                    
                    with self.lock:
                        self.update_flow_stats(output, current_time)
                        self.update_ai_data()
                
                # Print real-time statistics
                self.print_stats_realtime()
                            
            except Exception as e:
                print(f"Error collecting flow stats: {e}")
                
            time.sleep(1)

    def update_flow_stats(self, output, current_time):
        for line in output.split('\n'):
            if 'actions' not in line:
                continue
                
            try:
                match = {}
                for part in line.split(','):
                    if '=' in part:
                        k, v = part.split('=', 1)
                        match[k.strip()] = v.strip()

                if 'nw_src' in match and 'nw_dst' in match:
                    src_ip = match['nw_src']
                    dst_ip = match['nw_dst']
                    src_port = match.get('tp_src', '0')
                    dst_port = match.get('tp_dst', '0')
                    
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    stats = self.flows[flow_key]
                    
                    # Update packet and byte counts
                    if 'n_packets' in match:
                        packets = int(match['n_packets'])
                        bytes_count = int(match.get('n_bytes', 0))
                        
                        if packets > stats.fwd_pkts:
                            stats.fwd_pkts = packets
                            stats.fwd_bytes = bytes_count
                            if bytes_count > 0:
                                stats.fwd_pkt_lens.append(bytes_count / packets)
                        
                        # Update IAT
                        if stats.last_time < current_time:
                            stats.fwd_iat.append(current_time - stats.last_time)
                            stats.last_time = current_time
                    
                    # Update TCP flags if present
                    if 'tcp_flags' in match:
                        flags = int(match['tcp_flags'], 16)
                        self.update_tcp_flags(stats, flags)
                    
            except Exception as e:
                print(f"Error parsing flow entry: {e}")

    def update_tcp_flags(self, stats, flags):
        if flags & 0x002:  # SYN
            stats.syn_flags += 1
        if flags & 0x001:  # FIN
            stats.fin_flags += 1
        if flags & 0x004:  # RST
            stats.rst_flags += 1
        if flags & 0x008:  # PSH
            stats.fwd_psh_flags += 1
        if flags & 0x010:  # ACK
            stats.ack_flags += 1
        if flags & 0x020:  # URG
            stats.fwd_urg_flags += 1
        if flags & 0x040:  # CWE
            stats.cwe_flags += 1
        if flags & 0x080:  # ECE
            stats.ece_flags += 1

    def update_ai_data(self):
        self.ai_ready_data = []
        for flow_key, stats in self.flows.items():
            features = self.get_ai_features(flow_key, stats)
            if features:
                self.ai_ready_data.append(features)

    def export_ai_data(self, filename):
        """Export data in format ready for AI model"""
        if self.ai_ready_data:
            df = pd.DataFrame(self.ai_ready_data)
            df.to_csv(filename, index=False)
            print(f"\nAI-ready data exported to {filename}")
            return df
        return None

    def start_monitoring(self):
        self.stats_thread = threading.Thread(target=self.collect_flow_stats)
        self.stats_thread.daemon = True
        self.stats_thread.start()

    def stop_monitoring(self):
        self.running = False
        if hasattr(self, 'stats_thread'):
            self.stats_thread.join()

# Network creation and CLI remain the same as previous version
def create_network():
    net = Mininet(
        controller=OVSController,
        host=CPULimitedHost,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    
    info('*** Adding controller\n')
    net.addController('c0')
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    
    info('*** Adding hosts\n')
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')
    
    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(s1, s2)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    
    return net

def run_network():
    net = None
    monitor = None
    
    try:
        net = create_network()
        net.start()
        
        monitor = FlowMonitor(net)
        monitor.start_monitoring()
        
        print("\nNetwork is running with AI-ready flow monitoring!")
        print("Commands available:")
        print("  h1 ping h2")
        print("  h1 iperf -s &")
        print("  h2 iperf -c h1")
        print("  export - Export AI-ready data")
        
        class MonitorCLI(CLI):
            def do_export(self, _line):
                """Export current statistics in AI-ready format"""
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f'ai_ready_flow_stats_{timestamp}.csv'
                df = monitor.export_ai_data(filename)
                if df is not None:
                    print("\nFeature statistics:")
                    print(df.describe())
        
        MonitorCLI(net)
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if monitor:
            monitor.stop_monitoring()
        if net:
            net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_network()
