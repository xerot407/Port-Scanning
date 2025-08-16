import socket
import threading
from queue import Queue
import time
from typing import List, Dict, Tuple

class Scanner:
    """Base class for port scanning operations."""
    
    def __init__(self, target: str, timeout: float = 1.0):
        """
        Initialize the Scanner with target host and timeout.
        
        Args:
            target (str): Target hostname or IP address
            timeout (float): Connection timeout in seconds
        """
        self.target = target
        self.timeout = timeout
        self.ports_status: Dict[int, str] = {}

    def scan_port(self, port: int) -> bool:
        """
        Scan a single port on the target host.
        
        Args:
            port (int): Port number to scan
            
        Returns:
            bool: True if port is open, False otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((self.target, port))
            return result == 0
        except socket.gaierror:
            return False
        except socket.error:
            return False
        finally:
            sock.close()

class ThreadedPortScanner(Scanner):
    """Threaded port scanner inheriting from base Scanner class."""
    
    def __init__(self, target: str, threads: int = 100, timeout: float = 1.0):
        """
        Initialize the threaded port scanner.
        
        Args:
            target (str): Target hostname or IP address
            threads (int): Number of threads to use for scanning
            timeout (float): Connection timeout in seconds
        """
        super().__init__(target, timeout)
        self.threads = threads
        self.port_queue = Queue()
        self.lock = threading.Lock()

    def _scan_worker(self) -> None:
        """Worker function for scanning ports from the queue."""
        while not self.port_queue.empty():
            port = self.port_queue.get()
            status = "open" if self.scan_port(port) else "closed"
            with self.lock:
                self.ports_status[port] = status
            self.port_queue.task_done()

    def scan_range(self, start_port: int, end_port: int) -> Dict[int, str]:
        """
        Scan a range of ports using multiple threads.
        
        Args:
            start_port (int): Starting port number
            end_port (int): Ending port number
            
        Returns:
            Dict[int, str]: Dictionary of port numbers and their status
        """
        # Clear previous results
        self.ports_status.clear()
        
        # Fill queue with ports to scan
        for port in range(start_port, end_port + 1):
            self.port_queue.put(port)
        
        # Create and start threads
        threads = []
        for _ in range(min(self.threads, end_port - start_port + 1)):
            t = threading.Thread(target=self._scan_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        return self.ports_status

class PortScannerManager:
    """Manager class to handle port scanning operations and results."""
    
    def __init__(self, target: str, threads: int = 100, timeout: float = 1.0):
        """
        Initialize the port scanner manager.
        
        Args:
            target (str): Target hostname or IP address
            threads (int): Number of threads to use
            timeout (float): Connection timeout in seconds
        """
        self.scanner = ThreadedPortScanner(target, threads, timeout)
    
    def scan_common_ports(self) -> Dict[int, str]:
        """
        Scan commonly used ports.
        
        Returns:
            Dict[int, str]: Dictionary of port numbers and their status
        """
        common_ports = [21, 22, 23, 25, 80, 443, 3389]
        return self.scanner.scan_range(min(common_ports), max(common_ports))
    
    def scan_port_range(self, start_port: int, end_port: int) -> Dict[int, str]:
        """
        Scan a specified range of ports.
        
        Args:
            start_port (int): Starting port number
            end_port (int): Ending port number
            
        Returns:
            Dict[int, str]: Dictionary of port numbers and their status
        """
        return self.scanner.scan_range(start_port, end_port)
    
    def print_results(self, results: Dict[int, str]) -> None:
        """
        Print scanning results in a formatted manner.
        
        Args:
            results (Dict[int, str]): Dictionary of port numbers and their status
        """
        print(f"\nScan results for {self.scanner.target}:")
        print("-" * 40)
        print(f"{'Port':<10} {'Status':<10}")
        print("-" * 40)
        for port, status in sorted(results.items()):
            print(f"{port:<10} {status:<10}")

# Sample test cases with user input
if __name__ == "__main__":
    # Prompt user for IP address
    target_ip = input("Enter the IP address or hostname to scan (e.g., localhost or scanme.nmap.org): ").strip()
    
    # Test Case 1: Scanning common ports on user-specified target
    print(f"\nTest Case 1: Scanning common ports on {target_ip}")
    manager = PortScannerManager(target_ip, threads=50, timeout=0.5)
    results = manager.scan_common_ports()
    manager.print_results(results)
    
    # Test Case 2: Scanning a range of ports
    print(f"\nTest Case 2: Scanning ports 80-85 on {target_ip}")
    manager = PortScannerManager(target_ip, threads=50, timeout=0.5)
    results = manager.scan_port_range(80, 85)
    manager.print_results(results)
    
    # Test Case 3: Scanning with different thread count
    print(f"\nTest Case 3: Scanning with increased threads on {target_ip}")
    manager = PortScannerManager(target_ip, threads=200, timeout=0.3)
    start_time = time.time()
    results = manager.scan_port_range(1, 100)
    manager.print_results(results)
    print(f"Scan completed in {time.time() - start_time:.2f} seconds")