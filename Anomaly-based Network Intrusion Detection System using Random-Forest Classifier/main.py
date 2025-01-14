import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from scapy.all import IFACES
import pyshark
import threading
import subprocess
import asyncio
import os   
from datetime import datetime
import numpy as np
import pandas as pd
import pickle  
import csv
from playsound import playsound
from PIL import Image
import platform
from email.message import EmailMessage
import ssl
import smtplib
import re

## Global variables for backend functions
# To store the name selected interface to monitor
selected_interface = None
selected_pcap = None

email_sender = "teenloke22@gmail.com"
email_password = "rdacqqcxrhcivnsi"
email_receiver = ""

# Event for stopping the capture
stop_capture_flag = threading.Event()
capture_start = False  # To store the thread for capturing packets

# Global flags to control the threads
stop_monitor = False

# To handle location of external files
pcap_folder = 'pcap_files'
csv_folder = 'capturedflowcsv'
model_file = 'trainedrfcmodel.pkl'
alertsound = 'alertsound.mp3'
csv_path = None

# To store packet flows
flows = {}

# Threat Name, Threat Severity, Threat Description
threat_severity = [
    ["Benign", "None", "Normal network traffic behavior without malicious activities."],
    ["Bot", "Critical", "Compromised systems controlled by a botnet."],
    ["DDoS", "Critical", "A Distributed Denial of Service (DDoS) attack where multiple machines are used to flood and disrupt the server's operations."],
    ["DoS GoldenEye", "High", "A Denial of Service (DoS) attack utilizing the GoldenEye tool to overwhelm the server."],
    ["DoS Hulk", "High", "A Denial of Service (DoS) attack using the HULK tool to flood the web server with massive volumes of obfuscated traffic."],
    ["DoS Slowhttptest", "High", "An HTTP GET request-based attack that exploits the server's connection limits."],
    ["DoS Slowloris", "High", "The Slow Loris tool executes a denial of service attack by opening numerous connections and holding them open to exhaust the server's resources."],
    ["FTP-Patator", "Medium", "Brute force attack to guess FTP login credentials through repeated trial attempts."],
    ["Heartbleed", "Critical", "Attempt to exploit a vulnerability within the OpenSSL protocol that leaks information from the memory of systems."],
    ["Infiltration", "High", "Trying to infiltrate the network to gain unauthorized access and control over internal network."],
    ["PortScan", "Medium", "Attempt to gather information about this machine by scanning open ports and services."],
    ["SSH-Patator", "Medium", "Brute force SSH login credentials to exploit weak passwords and login attempts."],
    ["Web Attack - Brute Force", "Medium", "Attempts to steal sensitive information (e.g., passwords, PINs)."],
    ["Web Attack - XSS", "Medium", "Cross-Site Scripting (XSS) attack that injects malicious scripts into trusted websites to steal data or redirect users to malicious sites."],
    ["Web Attack - SQL Injection", "High", "Malicious SQL statements are inserted into an input field to manipulate and gain control over the database or execute unwanted commands."],
    ["Anomaly", "Critical", "Unusual behavior that deviates from normal network traffic behavior."]
]

packet_info = {
    'source_ip': 0,
    'destination_ip': 0,
    'source_port': 0,
    'destination_port': 0,
    'protocol': 0,
    'timestamp': 0,
    'flow_duration': 0,
    'total_fwd_packets': 0,  
    'total_backward_packets': 0, 
    'total_length_of_fwd_packets': 0,
    'total_length_of_bwd_packets': 0,
    'fwd_packet_length_max': 0,
    'fwd_packet_length_min': 0,
    'fwd_packet_length_mean': 0,
    'fwd_packet_length_std': 0,
    'bwd_packet_length_max': 0,
    'bwd_packet_length_min': 0,
    'bwd_packet_length_mean': 0,
    'bwd_packet_length_std': 0,
    'flow_bytes/s': 0,
    'flow_packets/s': 0,
    'flow_iat_mean': 0,
    'flow_iat_std': 0,
    'flow_iat_max': 0,
    'flow_iat_min': 0,
    'fwd_iat_total': 0,
    'fwd_iat_mean': 0,
    'fwd_iat_std': 0,
    'fwd_iat_max': 0,
    'fwd_iat_min': 0,
    'bwd_iat_total': 0,
    'bwd_iat_mean': 0,
    'bwd_iat_std': 0,
    'bwd_iat_max': 0,
    'bwd_iat_min': 0,
    'fwd_psh_flags': 0,
    'bwd_psh_flags': 0,
    'fwd_urg_flags': 0,
    'bwd_urg_flags': 0,
    'fwd_header_length': 0,
    'bwd_header_length': 0,
    'fwd_packets/s': 0,
    'bwd_packets/s': 0,
    'min_packet_length': 0,
    'max_packet_length': 0,
    'packet_length_mean': 0,
    'packet_length_std': 0,
    'packet_length_variance': 0,
    'fin_flag_count': 0,
    'syn_flag_count': 0,
    'rst_flag_count': 0,
    'psh_flag_count': 0,
    'ack_flag_count': 0,
    'urg_flag_count': 0,
    'cwe_flag_count': 0,
    'ece_flag_count': 0,
    'down/up_ratio': 0,
    'average_packet_size': 0,
    'avg_fwd_segment_size': 0,
    'avg_bwd_segment_size': 0,
    'fwd_avg_bytes/bulk': 0,
    'fwd_avg_packets/bulk': 0,
    'fwd_avg_bulk_rate': 0,
    'bwd_avg_bytes/bulk': 0,
    'bwd_avg_packets/bulk': 0,
    'bwd_avg_bulk_rate': 0,
    'subflow_fwd_packets': 0,
    'subflow_fwd_bytes': 0,
    'subflow_bwd_packets': 0,
    'subflow_bwd_bytes': 0,
    'init_win_bytes_forward': 0,
    'init_win_bytes_backward': 0,
    'act_data_pkt_fwd': 0,
    'min_seg_size_forward': 0,
    'active_mean': 0,
    'active_std': 0,
    'active_max': 0,
    'active_min': 0,
    'idle_mean': 0,
    'idle_std': 0,
    'idle_max': 0,
    'idle_min': 0,
    'label' : 'N/A'
}

## Global variables for frontend functions
# To hold the CSV data and column filters
header = []
csv_data = []
column_filters = {}

# Threat count
low_count = 0
medium_count = 0
high_count = 0
critical_count = 0

## FUNCTIONS

# Function to handle navigation to a different frame
def show_frame(frame):
    frame.tkraise()

# Function to get available network interfaces
def get_interfaces():
    try:
        interfaces = [iface.name for iface in IFACES.data.values()]
        # Add "Manual Packet Selection" to the list
        interfaces.append("Manual Packet Selection")
        return interfaces
    except Exception as e:
        messagebox.showerror("Error", f"Error fetching interfaces: {str(e)}")
        return []
    
def is_valid_email(email):
    # Regular expression to validate email
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

# Function to handle Start NIDS button click
def start_nids():
    global selected_interface, email_receiver

    selected_interface = interface_combobox.get()
    email_receiver = email_entry.get()

    if selected_interface:
        if is_valid_email(email_receiver):
            show_frame(nids_page)
            log_text_box.configure(state="normal")
            log_text_box.insert(ctk.END, f"Listening on {selected_interface}...\n[{get_current_time(1)}] NIDS is ready to go.\n")
            log_text_box.configure(state="disabled")
        else:
            messagebox.showwarning("Notice", "Please enter a valid email address.")
    else:
        messagebox.showwarning("Notice", "Please select a network interface.")

def capture_packets(selected_interface):
    global stop_capture_flag, model_file, pcap_folder, packet_info, csv_folder, csv_path, selected_pcap
    # Setup the event loop manually for the current thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        with open(model_file, 'rb') as file:
            model = pickle.load(file)
        with open('sc_ids.pkl','rb') as f:
            scaler = pickle.load(f)
    except Exception as e:
        messagebox.showerror("Error", f"Error loading model: {str(e)}")
        return
    
    csv_path = os.path.join(csv_folder, f'flow_{get_current_time(0)}.csv')

    # Write captured data to CSV file
    with open(csv_path, 'a', newline='') as csvfile:
        fieldnames = [
            'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'timestamp' , 'flow_duration',
            'total_fwd_packets', 'total_backward_packets', 'total_length_of_fwd_packets', 'total_length_of_bwd_packets',
            'fwd_packet_length_max', 'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std', 
            'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean', 
            'bwd_packet_length_std', 'flow_bytes/s', 'flow_packets/s', 'flow_iat_mean', 
            'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'fwd_iat_total', 'fwd_iat_mean', 
            'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min', 'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 
            'bwd_iat_max', 'bwd_iat_min', 'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags', 
            'fwd_header_length', 'bwd_header_length', 'fwd_packets/s', 'bwd_packets/s', 'min_packet_length', 
            'max_packet_length', 'packet_length_mean', 'packet_length_std', 'packet_length_variance', 
            'fin_flag_count', 'syn_flag_count', 'rst_flag_count', 'psh_flag_count', 'ack_flag_count', 
            'urg_flag_count', 'cwe_flag_count', 'ece_flag_count', 'down/up_ratio', 'average_packet_size', 
            'avg_fwd_segment_size', 'avg_bwd_segment_size', 'fwd_avg_bytes/bulk', 'fwd_avg_packets/bulk', 
            'fwd_avg_bulk_rate', 'bwd_avg_bytes/bulk', 'bwd_avg_packets/bulk', 'bwd_avg_bulk_rate', 
            'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes', 
            'init_win_bytes_forward', 'init_win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 
            'active_mean', 'active_std', 'active_max', 'active_min', 'idle_mean', 'idle_std', 'idle_max', 'idle_min', 'label'
        ]
    
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        if selected_interface == "Manual Packet Selection":
            capture = pyshark.FileCapture(selected_pcap)

            for packet in capture:
                if stop_capture_flag.is_set():  # Check if stop flag is set
                    break
                process_packet(packet,model,scaler,writer)
        else:
            pcap_path = os.path.join(pcap_folder, f'{get_current_time(0)}.pcap')

            capture = pyshark.LiveCapture(
            interface= selected_interface,
            output_file=pcap_path,
            bpf_filter='tcp or udp'
            )

            # Start sniffing packets continuously
            for packet in capture.sniff_continuously():
                if stop_capture_flag.is_set():  # Check if stop flag is set
                    break
                process_packet(packet,model,scaler,writer)

    capture.close()
    delete_csv()

def process_packet(packet,model,scaler,writer):
    try:
        # Extract key flow attributes (5 tuples)
        flow_key = (
            packet.ip.src if hasattr(packet, 'ip') else 'N/A',
            packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
            packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else 'N/A',
            packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else 'N/A',
            packet.highest_layer,
        )

        packet_info['source_ip'] = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
        packet_info['destination_ip'] = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
        src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else 'N/A',
        packet_info['source_port'] = src_port[0]
        packet_info['destination_port'] = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else 'N/A'
        packet_info['protocol'] = packet.transport_layer

        formatted_time = packet.sniff_time.strftime("%d/%m/%Y %I:%M:%S")
        formatted_time = formatted_time.lstrip("0").replace("/0", "/")
        packet_info['timestamp'] = formatted_time

        if flow_key not in flows:
            flows[flow_key] = {
                'start_time': packet.sniff_time,
                'end_time': packet.sniff_time,
                'total_forward_packets': 0,
                'total_backward_packets': 0,
                'total_forward_bytes': 0,
                'total_backward_bytes': 0,
                'fwd_header_length': 0,
                'bwd_header_length': 0,
                'fwd_packet_lengths': [],
                'bwd_packet_lengths': [],
                'iat_list': [],
                'fwd_iat_list': [],
                'bwd_iat_list': [],
                'length_list': [],
                'tcp_flags': {
                    'FIN': 0,
                    'SYN': 0,
                    'RST': 0,
                    'PSH': 0,
                    'ACK': 0,
                    'URG': 0,
                    'CWE': 0,
                    'ECE': 0,
                },
                'last_packet_time': packet.sniff_time,
                'last_fwd_packet_time': packet.sniff_time,
                'last_bwd_packet_time': packet.sniff_time,
                'flow_duration': 0,
                'idle_time': 0,
                'active_time': 0,
            }

        # Get the flow and update its statistics
        flow = flows[flow_key]

        # Calculate flow duration
        flow['end_time'] = packet.sniff_time
        flow['flow_duration'] = (flow['end_time'] - flow['start_time']).total_seconds() * 1000  # Duration in ms
        packet_info['flow_duration'] = flow['flow_duration']

        # Check packet direction
        if flow_key[0] == packet.ip.src:
            flow['total_forward_packets'] += 1
            flow['total_forward_bytes'] += int(packet.length)
            flow['fwd_header_length'] += int(packet.ip.hdr_len) if hasattr(packet.ip, 'hdr_len') else 0
            flow['fwd_packet_lengths'].append(int(packet.length))

            # Forward inter-arrival time
            fwd_iat = (packet.sniff_time - flow['last_fwd_packet_time']).total_seconds() * 1000
            flow['fwd_iat_list'].append(fwd_iat)
            flow['last_fwd_packet_time'] = packet.sniff_time
        else:
            flow['total_backward_packets'] += 1
            flow['total_backward_bytes'] += int(packet.length)
            flow['bwd_header_length'] += int(packet.ip.hdr_len) if hasattr(packet.ip, 'hdr_len') else 0
            flow['bwd_packet_lengths'].append(int(packet.length))

            # Backward inter-arrival time
            bwd_iat = (packet.sniff_time - flow['last_bwd_packet_time']).total_seconds() * 1000
            flow['bwd_iat_list'].append(bwd_iat)
            flow['last_bwd_packet_time'] = packet.sniff_time

        # Calculate packet length statistics (min, max, mean, std) for forward and backward directions
        if flow['fwd_packet_lengths']:
            packet_info['fwd_packet_length_max'] = np.max(flow['fwd_packet_lengths'])
            packet_info['fwd_packet_length_min'] = np.min(flow['fwd_packet_lengths'])
            packet_info['fwd_packet_length_mean'] = np.mean(flow['fwd_packet_lengths'])
            packet_info['fwd_packet_length_std'] = np.std(flow['fwd_packet_lengths'])
        
        if flow['bwd_packet_lengths']:
            packet_info['bwd_packet_length_max'] = np.max(flow['bwd_packet_lengths'])
            packet_info['bwd_packet_length_min'] = np.min(flow['bwd_packet_lengths'])
            packet_info['bwd_packet_length_mean'] = np.mean(flow['bwd_packet_lengths'])
            packet_info['bwd_packet_length_std'] = np.std(flow['bwd_packet_lengths'])
        
        # Calculate variance of packet lengths (for both forward and backward)
        all_packet_lengths = flow['fwd_packet_lengths'] + flow['bwd_packet_lengths']
        if all_packet_lengths:
            packet_info['packet_length_variance'] = np.var(all_packet_lengths)
        else:
            packet_info['packet_length_variance'] = 0

        # Calculate inter-arrival time statistics (for both forward and backward directions)
        if flow['fwd_iat_list']:
            packet_info['fwd_iat_total'] = np.sum(flow['fwd_iat_list'])
            packet_info['fwd_iat_mean'] = np.mean(flow['fwd_iat_list'])
            packet_info['fwd_iat_std'] = np.std(flow['fwd_iat_list'])
            packet_info['fwd_iat_max'] = np.max(flow['fwd_iat_list'])
            packet_info['fwd_iat_min'] = np.min(flow['fwd_iat_list'])

        if flow['bwd_iat_list']:
            packet_info['bwd_iat_total'] = np.sum(flow['bwd_iat_list'])
            packet_info['bwd_iat_mean'] = np.mean(flow['bwd_iat_list'])
            packet_info['bwd_iat_std'] = np.std(flow['bwd_iat_list'])
            packet_info['bwd_iat_max'] = np.max(flow['bwd_iat_list'])
            packet_info['bwd_iat_min'] = np.min(flow['bwd_iat_list'])
        
        # Capture TCP flags (SYN, ACK, FIN, RST)
        if hasattr(packet, 'tcp'):
            tcp_flags = int(packet.tcp.flags, 16)  # Convert to integer
            flow['tcp_flags']['FIN'] += (1 if tcp_flags & 0x01 else 0)
            flow['tcp_flags']['SYN'] += (1 if tcp_flags & 0x02 else 0)
            flow['tcp_flags']['RST'] += (1 if tcp_flags & 0x04 else 0)
            flow['tcp_flags']['PSH'] += (1 if tcp_flags & 0x08 else 0)
            flow['tcp_flags']['ACK'] += (1 if tcp_flags & 0x10 else 0)
            flow['tcp_flags']['URG'] += (1 if tcp_flags & 0x20 else 0)
            flow['tcp_flags']['CWE'] += (1 if tcp_flags & 0x40 else 0)
            flow['tcp_flags']['ECE'] += (1 if tcp_flags & 0x80 else 0)

        # Calculate inter-arrival time (IAT)
        current_iat = (packet.sniff_time - flow['last_packet_time']).total_seconds() * 1000  # IAT in ms
        flow['iat_list'].append(current_iat)
        flow['last_packet_time'] = packet.sniff_time

        # Calculate IAT statistics (mean, std, max, min)
        if len(flow['iat_list']) > 0:
            packet_info['flow_iat_mean'] = np.mean(flow['iat_list'])
            packet_info['flow_iat_std'] = np.std(flow['iat_list'])
            packet_info['flow_iat_max'] = np.max(flow['iat_list'])
            packet_info['flow_iat_min'] = np.min(flow['iat_list'])
        else:
            packet_info['flow_iat_mean'] = packet_info['flow_iat_std'] = packet_info['Flow IAT Max'] = packet_info['Flow IAT Min'] = 0

        packet_info['total_fwd_packets'] = flow['total_forward_packets']
        packet_info['total_backward_packets'] = flow['total_backward_packets']
        packet_info['total_length_of_fwd_packets'] = flow['total_forward_bytes']
        packet_info['total_length_of_bwd_packets'] = flow['total_backward_bytes']

        # Calculate Flow Bytes/s
        if flow['flow_duration'] > 0:
            packet_info['flow_bytes/s'] = (flow['total_forward_bytes'] + flow['total_backward_bytes']) / (flow['flow_duration'] / 1000)
        else:
            packet_info['flow_bytes/s'] = 0

        # Calculate Packet Rate
        if flow['flow_duration'] > 0:
            packet_info['flow_packets/s'] = (flow['total_forward_packets'] + flow['total_backward_packets']) / (flow['flow_duration'] / 1000)
        else:
            packet_info['flow_packets/s'] = 0

        # Add idle time (time between last two packets)
        if current_iat > 0:
            flow['idle_time'] += current_iat

        # Calculate active and idle times
        if len(flow['iat_list']) > 0:
            packet_info['active_mean'] = np.mean(flow['iat_list'])
            packet_info['active_std'] = np.std(flow['iat_list'])
            packet_info['active_max'] = np.max(flow['iat_list'])
            packet_info['active_min'] = np.min(flow['iat_list'])

            # Idle time is the sum of time between packets (when packets aren't sent/received)
            packet_info['idle_mean'] = packet_info['active_mean']
            packet_info['idle_std'] = packet_info['active_std']
            packet_info['idle_max'] = packet_info['active_max']
            packet_info['idle_min'] = packet_info['active_min']
        else:
            packet_info['active_mean'] = packet_info['active_std'] = packet_info['active_max'] = packet_info['active_min'] = 0
            packet_info['idle_mean'] = packet_info['idle_std'] = packet_info['idle_max'] = packet_info['idle_min'] = 0

        # Packet length statistics (min, max, mean, std)
        flow['length_list'].append(int(packet.length))
        if len(flow['length_list']) > 0:
            packet_info['min_packet_length'] = np.min(flow['length_list'])
            packet_info['max_packet_length'] = np.max(flow['length_list'])
            packet_info['packet_length_mean'] = np.mean(flow['length_list'])
            packet_info['packet_length_std'] = np.std(flow['length_list'])
        else:
            packet_info['min_packet_length'] = packet_info['max_packet_length'] = packet_info['packet_length_mean'] = packet_info['packet_length_std'] = 0

        # Update subflow stats
        packet_info['subflow_fwd_packets'] = flow['total_forward_packets']
        packet_info['subflow_fwd_bytes'] = flow['total_forward_bytes']
        packet_info['subflow_bwd_packets'] = flow['total_backward_packets']
        packet_info['subflow_bwd_bytes'] = flow['total_backward_bytes']

        # Calculate Down/Up ratio
        if flow['total_backward_packets'] > 0:
            packet_info['down/up_ratio'] = flow['total_forward_packets'] / flow['total_backward_packets']
        else:
            packet_info['down/up_ratio'] = flow['total_forward_packets']

        # Header lengths
        packet_info['fwd_header_length'] = flow['fwd_header_length']
        packet_info['bwd_header_length'] = flow['bwd_header_length']

        # TCP flags and control information
        packet_info['fin_flag_count'] = flow['tcp_flags']['FIN']
        packet_info['syn_flag_count'] = flow['tcp_flags']['SYN']
        packet_info['rst_flag_count'] = flow['tcp_flags']['RST']
        packet_info['psh_flag_count'] = flow['tcp_flags']['PSH']
        packet_info['ack_flag_count'] = flow['tcp_flags']['ACK']
        packet_info['urg_flag_count'] = flow['tcp_flags']['URG']
        packet_info['cwe_flag_count'] = flow['tcp_flags']['CWE']
        packet_info['ece_flag_count'] = flow['tcp_flags']['ECE']

        # Calculate forward and backward segment sizes (average and minimum)
        if flow['fwd_packet_lengths']:
            packet_info['avg_fwd_segment_size'] = np.mean(flow['fwd_packet_lengths'])
            packet_info['min_seg_size_forward'] = np.min(flow['fwd_packet_lengths'])

        if flow['bwd_packet_lengths']:
            packet_info['avg_bwd_segment_size'] = np.mean(flow['bwd_packet_lengths'])

        # Calculate forward and backward bulk metrics (if needed in the setup)
        if len(flow['fwd_packet_lengths']) > 0:
            packet_info['fwd_avg_bytes/bulk'] = np.mean(flow['fwd_packet_lengths'])  # Placeholder example
            packet_info['fwd_avg_packets/bulk'] = len(flow['fwd_packet_lengths'])  # Placeholder example
            packet_info['fwd_avg_bulk_rate'] = packet_info['fwd_avg_bytes/bulk'] / flow['flow_duration'] if flow['flow_duration'] > 0 else 0

        if len(flow['bwd_packet_lengths']) > 0:
            packet_info['bwd_avg_bytes/bulk'] = np.mean(flow['bwd_packet_lengths'])  # Placeholder example
            packet_info['bwd_avg_packets/bulk'] = len(flow['bwd_packet_lengths'])  # Placeholder example
            packet_info['bwd_avg_bulk_rate'] = packet_info['bwd_avg_bytes/bulk'] / flow['flow_duration'] if flow['flow_duration'] > 0 else 0

        # Initial forward/backward window bytes
        if hasattr(packet, 'tcp'):
            packet_info['init_win_bytes_forward'] = packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else 0
            packet_info['init_win_bytes_backward'] = packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else 0

        # Prepare dataframe for prediction
        df = pd.DataFrame(packet_info, index=[0])
        df = df.drop(columns=['source_ip','source_port','destination_ip','protocol','timestamp','label'], axis=1)

        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = pd.to_numeric(df[col], errors='coerce').astype('int64')
            elif df[col].dtype == 'int32':
                df[col] = df[col].astype('int64')
        
        cols = df.select_dtypes(include=['float64','int64']).columns
        sc = scaler.transform(df)
        sc_df = pd.DataFrame(sc, columns = cols)

        # Predict                
        predictions = model.predict(sc_df)

        try:
            # Find the index of the first occurrence of 1.0 in the list
            threat_index = predictions.tolist()[0].index(1.0)
        except ValueError:
            # If 1.0 is not found, assign a default value (e.g., 15)
            threat_index = 15

        # Update list
        packet_info['label'] = threat_severity[threat_index][0]

        # Categorize prediction
        categorize_packet(threat_index,writer)

        update_threat_count(threat_severity[threat_index][1])

    except AttributeError:
        # Ignore packets without IP layer information
        pass

# Categorize and log threat
def categorize_packet(threat_index,writer):
    global packet_info

    # Log threat details if a valid index is found
    if threat_index is not None and threat_index != 0 and threat_index < len(threat_severity):
        threat = threat_severity[threat_index]
        log_text_box.configure(state="normal")
        log_text_box.insert(ctk.END, f"[{get_current_time(1)}] THREAT DETECTED! \n{threat[2]} \nClassification: {threat[0]} (Severity: {threat[1]}) \n{packet_info['protocol']} {packet_info['source_ip']}:{packet_info['source_port']} > {packet_info['destination_ip']}:{packet_info['destination_port']}\n")
        log_text_box.configure(state="disabled")
        writer.writerow(packet_info)
        if threat[1] == "High" or threat[1] == "Critical":
            alert_user()
            email_alert(threat)
    if show_traffic_switch.get() and threat_index == 0:
        log_text_box.configure(state="normal")
        log_text_box.insert(ctk.END, f"[{get_current_time(1)}] {packet_info['protocol']} {packet_info['source_ip']}:{packet_info['source_port']} > {packet_info['destination_ip']}:{packet_info['destination_port']}\n")
        log_text_box.configure(state="disabled")

def alert_user():
    global alertsound
    playsound(alertsound)

def email_alert(threat):
    subject = f"[{threat[1].upper()} SEVERITY] Potential Network Intrusion Detected"
    body = f"""
    This is an automated alert from the Network Intrusion Detection System (NIDS). A potential network intrusion has been detected. Please review the details below and take appropriate action.
    
    Alert Details:
    Threat Level: Severity Level - {threat[1]}
    Detection Time: {packet_info['timestamp']}
    Source IP: {packet_info['source_ip']}
    Destination IP: {packet_info['destination_ip']}
    Protocol: {packet_info['protocol']}
    Attack Type**: {threat[0]}
    Details: {threat[2]}

    Please ensure that appropriate steps are taken to mitigate the potential threat.

    Best regards,  
    Your NIDS System
    """

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())

def open_file_explorer(path):
    # Get the current operating system
    system_name = platform.system()

    try:
        if system_name == "Windows":
            # Windows
            os.startfile(os.path.abspath(path))
        elif system_name == "Darwin":
            # macOS
            subprocess.Popen(["open", os.path.abspath(path)])
        elif system_name == "Linux":
            # Linux
            subprocess.Popen(["xdg-open", os.path.abspath(path)])
        else:
            print("Unsupported operating system")
    except Exception as e:
        print(f"Error opening file explorer: {e}")

def delete_csv():
    global csv_path
    try:
        with open(csv_path, 'r') as csvfile:
            # Count the number of lines in the file
            lines = csvfile.readlines()
    except Exception as e:
        print(f"Error checking CSV file: {e}")
    if len(lines) <= 1:
        # If only the header exists, delete the file
        print(f"CSV file contains only the header, deleting {csv_path}")
        os.remove(csv_path)
    else:
        print(f"CSV file has data, keeping {csv_path}")

# Function to handle Start Detection button click
def start_detection():
    global stop_capture_flag, capture_start, selected_pcap

    if capture_start:
        messagebox.showinfo("Notice", "NIDS has already started monitoring.")
    elif selected_interface:
        if selected_interface == "Manual Packet Selection":
            selected_pcap = None
            open_pcap_file()
            if selected_pcap == None:
                return
        stop_capture_flag.clear()
        capture_thread = threading.Thread(target=capture_packets, args=(selected_interface,))
        capture_thread.daemon = True
        capture_thread.start()
        capture_start = True
        #messagebox.showinfo("Start Detection", "Network Intrusion Detection Started.")
        system_status_label.configure(text="System Status: Running")
        log_text_box.configure(state="normal")
        log_text_box.insert(ctk.END,f"[{get_current_time(1)}] NIDS has started monitoring.\n")
        log_text_box.configure(state="disabled")
        log_text_box.see(ctk.END)


# Function to handle Stop Detection button click
def stop_detection():
    global stop_capture_flag, capture_start

    if capture_start:
        if messagebox.askokcancel("Stop Detection", "Do you want to stop?"):
            stop_capture_flag.set()
            capture_start = False
            system_status_label.configure(text="System Status: Stopped")
            log_text_box.configure(state="normal")
            log_text_box.insert(ctk.END,f"[{get_current_time(1)}] NIDS has stopped monitoring.\n")
            log_text_box.configure(state="disabled")
            log_text_box.see(ctk.END)
    else:
        messagebox.showinfo("Notice", "NIDS has not started monitoring yet.")

def back_main():
    if capture_start:
        messagebox.showinfo("Notice", "NIDS is still monitoring.")
    else:
        log_text_box.configure(state="normal")
        log_text_box.delete("0.0", "end")
        log_text_box.configure(state="disabled")
        show_frame(main_menu)

# Function to handle Quit button click
def on_closing():
    if capture_start:
        messagebox.showinfo("Notice", "NIDS is still monitoring.")
    else:
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            root.destroy()
            exit()

def get_current_time(choice):
    if choice == 0:
        return datetime.now().strftime('%d-%m-%Y_%H-%M-%S-%f')  # Format the current date and time
    elif choice == 1:
        return datetime.now().strftime('%H:%M:%S')  # Format the current date and time

def update_threat_count(threat_level):
    global low_count, medium_count, high_count, critical_count

    if threat_level == "Low":
        low_count += 1
        low_number_label.configure(text=str(low_count))
    elif threat_level == "Medium":
        medium_count += 1
        med_number_label.configure(text=str(medium_count))
    elif threat_level == "High":
        high_count += 1
        high_number_label.configure(text=str(high_count))
    elif threat_level == "Critical":
        critical_count += 1
        crit_number_label.configure(text=str(critical_count))

# Function to list the files in the folder
def open_csv_file():
    global csv_folder
    csvfile_path = filedialog.askopenfilename(title="Open CSV File", initialdir=csv_folder)

    if not csvfile_path:
        return  # Exit the function if no file was selected

    if csvfile_path and os.path.commonpath([os.path.abspath(csvfile_path), os.path.abspath(csv_folder)]) == os.path.abspath(csv_folder):
        if csvfile_path.endswith('.csv'):
            display_csv_data(csvfile_path)
        else: 
            messagebox.showinfo("Notice", "Please select a CSV file.")
    else:
        messagebox.showinfo("Notice", "Please select a file within the specified directory.")

def open_pcap_file():
    global csv_folder,selected_pcap
    pcapfile_path = filedialog.askopenfilename(title="Open PCAP File", initialdir=pcap_folder)

    if not pcapfile_path:
        return  # Exit the function if no file was selected

    if pcapfile_path and os.path.commonpath([os.path.abspath(pcapfile_path), os.path.abspath(pcap_folder)]) == os.path.abspath(pcap_folder):
        if pcapfile_path.endswith('.pcap'):
            selected_pcap = pcapfile_path
        else: 
            messagebox.showinfo("Notice", "Please select a PCAP file.")
    else:
        messagebox.showinfo("Notice", "Please select a file within the specified directory.")

def display_csv_data(file_path):
    global header, csv_data
    try:
        with open(file_path, 'r', newline='') as file:
            csv_reader = csv.reader(file)
            header = next(csv_reader)  # Read the header row
            csv_data = list(csv_reader)  # Read all rows
            
            # Clear the treeview
            tree.delete(*tree.get_children())

            # Configure tree columns with a fixed minimum width for headers
            tree["columns"] = header
            min_width = 150  # Set a minimum width for columns to ensure headers are visible
            for col in header:
                tree.heading(col, text=col)
                tree.column(col, anchor="center", width=min_width, minwidth=min_width)

            # Insert the data into the treeview
            for row in csv_data:
                tree.insert("", "end", values=row)

            # Update the checkboxes for filtering
            update_filter_checkboxes()

            csv_status_label.configure(text=f"CSV file loaded: {file_path}")
    
    except Exception as e:
        csv_status_label.configure(text=f"Error: This is not a csv file")

def update_filter_checkboxes():
    # Clear any existing checkboxes
    for widget in checkbox_frame.winfo_children():
        widget.destroy()

    # Set the number of columns per row
    max_columns_per_row = 8  # Adjust this value to control how many checkboxes appear per row

    # Create a checkbox for each column and arrange them in a grid
    for index, col in enumerate(header):
        var = tk.BooleanVar(value=True)  # Default to showing all columns
        checkbox = ctk.CTkCheckBox(checkbox_frame, text=col, variable=var, command=filter_columns)
        checkbox.var = var
        checkbox.col = col

        # Use grid layout to stack checkboxes
        row = index // max_columns_per_row
        column = index % max_columns_per_row
        checkbox.grid(row=row, column=column, sticky="w", padx=5, pady=5)

        column_filters[col] = var

def filter_columns():
    # Get which columns are checked (selected to display)
    selected_columns = [col for col, var in column_filters.items() if var.get()]

    # Clear the treeview and set new columns
    tree.delete(*tree.get_children())
    tree["columns"] = selected_columns

    for col in selected_columns:
        tree.heading(col, text=col)
        tree.column(col, width=150, anchor="center")

    # Reinsert data based on the selected columns
    for row in csv_data:
        filtered_row = [row[header.index(col)] for col in selected_columns]
        tree.insert("", "end", values=filtered_row)

def search_data():
    # Get the search term from the entry box
    search_term = search_entry.get().lower()

    # Clear the treeview
    tree.delete(*tree.get_children())

    # Search through the CSV data and insert matching rows
    for row in csv_data:
        if any(search_term in str(cell).lower() for cell in row):  # Check if search term matches any cell
            tree.insert("", "end", values=row)

# Helper function to create a frame with a large number and a word underneath
def create_threat_label(frame, threat_name, count, color):
    sub_frame = ctk.CTkFrame(frame, fg_color=color, corner_radius=15, width=180, height=180)
    sub_frame.grid_propagate(False)  # Prevent resizing of the frame
    sub_frame.pack_propagate(False)  # Prevent the label from resizing the frame
    
    # Create a container frame inside for centering the text
    inner_frame = ctk.CTkFrame(sub_frame, fg_color=color)
    inner_frame.pack(expand=True, fill="both")  # This allows for vertical centering

    # Create the larger text (number) label and center it vertically
    number_label = ctk.CTkLabel(inner_frame, text=str(count), font=ctk.CTkFont(size=90), text_color="black")
    number_label.pack(side="top", pady=(20, 0))  # Add some top padding
    
    # Create the smaller text (word) label and center it vertically
    word_label = ctk.CTkLabel(inner_frame, text=threat_name, font=ctk.CTkFont(size=20, weight="bold"), text_color="black")
    word_label.pack(side="top", pady=(0, 20))  # Add bottom padding
    
    return sub_frame, number_label

# Initialize the main window
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("Network Intrusion Detection System")

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
position_x = int((screen_width / 2) - (1150 / 2))
position_y = int((screen_height / 2) - (800 / 2))
root.geometry(f"1140x800+{position_x}+{position_y}")

# Create two frames (pages)
main_menu = ctk.CTkFrame(root, corner_radius=10)
nids_page = ctk.CTkFrame(root, corner_radius=10)
logs_page = ctk.CTkFrame(root, corner_radius=10)

# Configure grid weights to center the frames
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

for frame in (main_menu, nids_page, logs_page):
    frame.grid(row=0, column=0, sticky='nsew')

# Function to update the color of the switch when toggled
def toggle_switch():
    if show_traffic_switch.get():
        show_traffic_switch.configure(button_color="#337cc4")  # Blue when switched on
    else:
        show_traffic_switch.configure(button_color="grey")

def still_running():
    if capture_start:
        log_nids_remind_label.grid(row=0, column=0, pady=(0,10), sticky="nsew")
        show_frame(logs_page)
    else:
        log_nids_remind_label.grid_remove()
        show_frame(logs_page)

## Main Menu Page ##

# Load the image using PIL
image = Image.open("logo.png")  # Replace with the path to your image

# Convert the image to be compatible with CTk
ctk_image_main = ctk.CTkImage(image, size=(270, 270))  # Specify the size of the image

# Create a label and display the image
image_label = ctk.CTkLabel(main_menu, image=ctk_image_main, text="")  # Text is set to empty to show only the image
image_label.pack(pady=(60,0))

title_label = ctk.CTkLabel(main_menu, text="Network Intrusion Detection System", font=ctk.CTkFont(size=34, weight="bold"))
title_label.pack(pady=(40,60))

input_label = ctk.CTkLabel(main_menu, text="Select a Network Interface to Monitor:", font=ctk.CTkFont(size=16))
input_label.pack()

# Combobox for selecting network interface
interfaces = get_interfaces()
interface_combobox = ctk.CTkComboBox(main_menu, values=interfaces, width=350, height=40, font=ctk.CTkFont(size=14), state="readonly")
interface_combobox.pack(pady=(20,40))

email_label = ctk.CTkLabel(main_menu, text="Enter your email for threat alerts:", font=ctk.CTkFont(size=16))
email_label.pack()

email_entry = ctk.CTkEntry(main_menu, width=350, height=40)
email_entry.pack(padx=20, pady=(20))

start_button = ctk.CTkButton(main_menu, text="Start NIDS", command=start_nids, font=ctk.CTkFont(size=16), width=180, height=40)
start_button.pack(pady=20)

## NIDS Page ##

mon_navigation_frame = ctk.CTkFrame(nids_page)
mon_navigation_frame.pack(fill="x")

ctk_image_nids = ctk.CTkImage(image, size=(60, 60))

mon_image_label = ctk.CTkLabel(mon_navigation_frame, image=ctk_image_nids, text="")  # Text is set to empty to show only the image
mon_image_label.grid(row=0, column=0, padx=(0,10))  # Place in the first column of row 0

mon_nids_title_label = ctk.CTkLabel(mon_navigation_frame, text="Network Intrusion Detection System", font=ctk.CTkFont(size=18, weight="bold"))
mon_nids_title_label.grid(row=0, column=1, padx=(10,20), pady=15, sticky="w")

mon_monitor_button = ctk.CTkButton(mon_navigation_frame, text="Monitor", width=180, height=60, fg_color="transparent", hover_color="#999999", text_color="black", corner_radius=0, font=ctk.CTkFont(size=16))
mon_monitor_button.grid(row=0, column=2, padx=0)

mon_detected_button = ctk.CTkButton(mon_navigation_frame, text="Detected Flows", command=still_running, width=180, height=60, hover_color="#999999", fg_color="transparent", text_color="black", corner_radius=0, font=ctk.CTkFont(size=16))
mon_detected_button.grid(row=0, column=3, padx=0)

mon_cap_pcap_button = ctk.CTkButton(mon_navigation_frame, text="Captured PCAPs", command=lambda: open_file_explorer(pcap_folder), width=180, height=60, fg_color="transparent", hover_color="#999999", text_color="black", corner_radius=0, font=ctk.CTkFont(size=16))
mon_cap_pcap_button.grid(row=0, column=4, padx=0)

mon_back_button = ctk.CTkButton(mon_navigation_frame, text="Back to Main Menu",command=back_main, width=180, height=60, fg_color="transparent", hover_color="#999999", text_color="black", corner_radius=0, font=ctk.CTkFont(size=16))
mon_back_button.grid(row=0, column=5, padx=0)

# Create a frame to hold the labels
threat_frame = ctk.CTkFrame(nids_page, fg_color="lightgray")
threat_frame.pack(pady=40, padx=20)

# Create threat level labels with the number on top and word on the bottom
low_label_frame, low_number_label = create_threat_label(threat_frame, "Low", low_count, "#eddd8a")
low_label_frame.grid(row=0, column=0, padx=(10, 10))

med_label_frame, med_number_label = create_threat_label(threat_frame, "Medium", medium_count, "#edb077")
med_label_frame.grid(row=0, column=1, padx=(10, 10))

high_label_frame, high_number_label = create_threat_label(threat_frame, "High", high_count, "#d96666")
high_label_frame.grid(row=0, column=2, padx=(10, 10))

crit_label_frame, crit_number_label = create_threat_label(threat_frame, "Critical", critical_count, "#8f433c")
crit_label_frame.grid(row=0, column=3, padx=(10, 10))

system_status_label = ctk.CTkLabel(nids_page, text="System Status: Idle", font=ctk.CTkFont(size=18))
system_status_label.pack(pady=10)

# Button Frame with Start, Stop, and View Logs buttons
button_frame = ctk.CTkFrame(nids_page)
button_frame.pack(pady=30)

start_detection_button = ctk.CTkButton(button_frame, text="Start Detection", command=start_detection, width=180, height=40, font=ctk.CTkFont(size=16))
start_detection_button.grid(row=0, column=0, padx=10)

stop_detection_button = ctk.CTkButton(button_frame, text="Stop Detection", command=stop_detection, width=180, height=40, font=ctk.CTkFont(size=16))
stop_detection_button.grid(row=0, column=1, padx=10)

# Larger log display box for better visibility
log_text_box = ctk.CTkTextbox(nids_page, height=240, width=800, corner_radius=10)
log_text_box.pack(pady=10)
log_text_box.configure(state="disabled")

# Add the "Show Normal Traffic" switch below the text box
show_traffic_switch = ctk.CTkSwitch(nids_page, text="Show Normal Traffic", command=toggle_switch)
show_traffic_switch.pack(padx=(600,0), pady=(5,30))


## Log Files Page ##

log_navigation_frame = ctk.CTkFrame(logs_page)
log_navigation_frame.pack(fill="x")

log_image_label = ctk.CTkLabel(log_navigation_frame, image=ctk_image_nids, text="")  # Text is set to empty to show only the image
log_image_label.grid(row=0, column=0, padx=(0,10))  # Place in the first column of row 0

log_nids_title_label = ctk.CTkLabel(log_navigation_frame, text="Network Intrusion Detection System", font=ctk.CTkFont(size=18, weight="bold"))
log_nids_title_label.grid(row=0, column=1, padx=(10,20), pady=15, sticky="w")

log_monitor_button = ctk.CTkButton(log_navigation_frame, text="Monitor", command=lambda: show_frame(nids_page), width=180, height=60, fg_color="transparent", hover_color="#999999", text_color="black", corner_radius=0, font=ctk.CTkFont(size=16))
log_monitor_button.grid(row=0, column=2, padx=0)

log_detected_button = ctk.CTkButton(log_navigation_frame, text="Detected Flows", command=still_running, width=180, height=60, hover_color="#999999", fg_color="transparent", text_color="black", corner_radius=0, font=ctk.CTkFont(size=16))
log_detected_button.grid(row=0, column=3, padx=0)

log_cap_pcap_button = ctk.CTkButton(log_navigation_frame, text="Captured PCAPs", command=lambda: open_file_explorer(pcap_folder), width=180, height=60, fg_color="transparent", hover_color="#999999", text_color="black", corner_radius=0, font=ctk.CTkFont(size=16))
log_cap_pcap_button.grid(row=0, column=4, padx=0)

log_back_button = ctk.CTkButton(log_navigation_frame, text="Back to Main Menu",command=back_main, width=180, height=60, fg_color="transparent", hover_color="#999999", text_color="black", corner_radius=0, font=ctk.CTkFont(size=16))
log_back_button.grid(row=0, column=5, padx=0)

log_nids_remind_frame = ctk.CTkFrame(logs_page, height=1, fg_color="transparent")
log_nids_remind_frame.grid_rowconfigure(0, weight=1)  # Make row 0 expand
log_nids_remind_frame.grid_columnconfigure(0, weight=1)  # Make column 0 expand
log_nids_remind_frame.pack(fill="x")

log_nids_remind_label = ctk.CTkLabel(log_nids_remind_frame, text="NIDS is still monitoring!", fg_color="#c74046", font=ctk.CTkFont(size=14, weight="bold"))

# Entry box and button for search (using CTkEntry and CTkButton)

search_frame = ctk.CTkFrame(logs_page, fg_color="transparent")
search_frame.pack(pady=(40,10))

search_entry = ctk.CTkEntry(search_frame)
search_entry.grid(row=0, column=0, padx=20)

search_button = ctk.CTkButton(search_frame, text="Search", command=search_data, width=100)
search_button.grid(row=0, column=1, padx=10)

# Create a frame to hold the treeview and scrollbars
treeframe = ctk.CTkFrame(logs_page)
treeframe.pack(padx=20, pady=(0,20), fill="both", expand=True)

# Create the treeview widget (using ttk since ctk doesn't have a treeview)
tree = ttk.Treeview(treeframe, show="headings")

# Create vertical scrollbar
vsb = ttk.Scrollbar(treeframe, orient="vertical", command=tree.yview)
vsb.pack(side="right", fill="y")

# Create horizontal scrollbar
hsb = ttk.Scrollbar(treeframe, orient="horizontal", command=tree.xview)
hsb.pack(side="bottom", fill="x")

# Configure the treeview to use the scrollbars
tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
tree.pack(fill="both", expand=True)

# Button to open CSV file (CTkButton instead of standard Tkinter button)
open_button = ctk.CTkButton(logs_page, text="Open CSV File", command=open_csv_file, width=180, height=40, font=ctk.CTkFont(size=16))
open_button.pack(padx=20, pady=(0,10))

# Frame to hold checkboxes for column filtering (CTkFrame)
checkbox_frame = ctk.CTkFrame(logs_page)
checkbox_frame.pack(padx=20, pady=10)

# Status label (CTkLabel instead of Tkinter label)
csv_status_label = ctk.CTkLabel(logs_page, text="", padx=20, pady=10)
csv_status_label.pack()

# Function to handle navigation to different frames
def show_frame(frame):
    frame.tkraise()

# Show the main menu frame initially
show_frame(main_menu)

# Stop program when Tkinter is closed
root.protocol("WM_DELETE_WINDOW", on_closing)

# Start the Tkinter event loop
root.mainloop()