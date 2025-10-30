import requests
import json

# The URL where your FastAPI server is running
API_BASE_URL = "http://127.0.0.1:8000/api/v1"

def print_header(title):
    print("\n" + "="*30)
    print(f" {title} ")
    print("="*30)

def get_all_assets():
    """Fetches and prints all assets from the server."""
    try:
        response = requests.get(f"{API_BASE_URL}/assets/")
        response.raise_for_status()  # Raise an error for bad status codes
        
        assets = response.json()
        print_header("Current Assets in Registry")
        if not assets:
            print("No assets found.")
            return

        for asset in assets:
            print(f"- ID: {asset['id']}, Name: {asset['device_name']} ({asset['serial_number']})")
            print(f"  User: {asset['allocated_user']}, Dept: {asset['department']}\n")
            
    except requests.exceptions.RequestException as e:
        print(f"Error fetching assets: {e}")

def create_new_asset():
    """Creates a new sample asset."""
    print_header("Creating New Asset")
    
    new_laptop = {
        "serial_number": "SN-TEST-12345",
        "device_name": "DEV-LAPTOP-001",
        "make": "Dell",
        "model": "XPS 15",
        "allocated_user": "John Doe",
        "location": "HQ - Office 201",
        "ip_address": "192.168.1.50",
        "value_zar": 35000.0,
        "department": "Development"
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/assets/", json=new_laptop)
        
        if response.status_code == 200:
            created_asset = response.json()
            print(f"Successfully created asset with ID: {created_asset['id']}")
        else:
            print(f"Failed to create asset. Status: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"Error creating asset: {e}")

if __name__ == "__main__":
    # 1. Create a new asset
    create_new_asset()
    
    # 2. Get and display all assets
    get_all_assets()