# agent/system_info.py
import platform
import socket
import uuid
import psutil

def get_system_info():
    """Gather comprehensive system information"""
    try:
        # Network information
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        
        # MAC address
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                               for elements in range(0,2*6,2)][::-1])
        
        # OS information
        os_version = f"{platform.system()} {platform.release()} {platform.version()}"
        
        return {
            "hostname": hostname,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "os_version": os_version,
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "total_memory": psutil.virtual_memory().total,
            "total_disk": psutil.disk_usage('/').total if hasattr(psutil, 'disk_usage') else 0
        }
    except Exception as e:
        print(f"Error gathering system info: {e}")
        return {}