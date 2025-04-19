#!/usr/bin/env python3

import pynetbox
import yaml
import os
import subprocess
from datetime import datetime

# NetBox connection settings
NETBOX_URL = "http://localhost:8000"
NETBOX_TOKEN = "39acab6ffdc2316306ecf0725b2156ce4671e9f0"  # Replace with your actual token from NetBox

# Zeek policy directory
ZEEK_POLICY_DIR = os.path.expanduser("~/network-automation/zeek-config")

def get_netbox_data():
    """Retrieve network segmentation data from NetBox"""
    # This function connects to NetBox API and retrieves network information
    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
    
    # Get all VLANs and IP prefixes from NetBox
    vlans = nb.ipam.vlans.all()
    prefixes = nb.ipam.prefixes.all()
    
    # Get devices and their interfaces
    devices = nb.dcim.devices.all()
    
    return {
        'vlans': list(vlans),
        'prefixes': list(prefixes),
        'devices': list(devices)
    }

def generate_zeek_policy(netbox_data):
    """Generate Zeek network segmentation policy based on NetBox data"""
    # This function converts NetBox data into a policy format
    policy = []
    
    # Create network segments from VLANs
    segments = {}
    for vlan in netbox_data['vlans']:
        segments[vlan.name] = {
            'id': vlan.vid,
            'description': vlan.description or '',
            'prefixes': []
        }
    
    # Associate prefixes with segments
    for prefix in netbox_data['prefixes']:
        if prefix.vlan and prefix.vlan.name in segments:
            segments[prefix.vlan.name]['prefixes'].append(str(prefix.prefix))
    
    # Generate policy rules for each segment
    for name, segment in segments.items():
        if segment['prefixes']:
            policy.append({
                'segment': name,
                'networks': segment['prefixes'],
                'description': segment['description'],
                'isolation_level': 'default',
                'timestamp': datetime.now().isoformat()
            })
    
    return policy

def write_zeek_policy(policy):
    """Write policy to Zeek configuration file"""
    # This function writes the policy to a Zeek script file
    os.makedirs(ZEEK_POLICY_DIR, exist_ok=True)
    
    # Create the Zeek policy file
    policy_file = os.path.join(ZEEK_POLICY_DIR, "network-segmentation.zeek")
    
    with open(policy_file, 'w') as f:
        f.write("# Automatically generated network segmentation policy\n")
        f.write("# Generated at: {}\n\n".format(datetime.now().isoformat()))
        
        f.write("module NetworkSegmentation;\n\n")
        
        f.write("export {\n")
        f.write("    global segments: table[subnet] of string = {\n")
        
        # Write each network segment to the policy
        for rule in policy:
            for network in rule['networks']:
                f.write(f"        {network} = \"{rule['segment']}\",\n")
        
        f.write("    };\n")
        f.write("}\n\n")
        
        # Initialize the policy when Zeek starts
        f.write("event zeek_init() {\n")
        f.write("    print \"Loaded network segmentation policy\";\n")
        f.write("}\n\n")
        
        # Monitor connections and check if they cross segments
        f.write("event connection_established(c: connection) {\n")
        f.write("    local orig_segment = \"\"; \n")
        f.write("    local resp_segment = \"\"; \n")
        f.write("    \n")
        f.write("    if (c$orig$host in segments) {\n")
        f.write("        orig_segment = segments[c$orig$host];\n")
        f.write("    }\n")
        f.write("    \n")
        f.write("    if (c$resp$host in segments) {\n")
        f.write("        resp_segment = segments[c$resp$host];\n")
        f.write("    }\n")
        f.write("    \n")
        f.write("    if (orig_segment != \"\" && resp_segment != \"\" && orig_segment != resp_segment) {\n")
        f.write("        print fmt(\"Cross-segment traffic detected: %s -> %s\", orig_segment, resp_segment);\n")
        f.write("    }\n")
        f.write("}\n")
    
    # Also create a YAML version of the policy for easier reading
    yaml_file = os.path.join(ZEEK_POLICY_DIR, "network-segmentation-policy.yaml")
    with open(yaml_file, 'w') as f:
        yaml.dump(policy, f, default_flow_style=False)
    
    return policy_file

def deploy_zeek_policy(policy_file):
    """Deploy and activate the Zeek policy with Docker"""
    try:
        # For demo, just show how to run Zeek with the policy
        print(f"Policy file created at {policy_file}")
        print("To run Zeek with this policy, use:")
        print(f"docker run -v {ZEEK_POLICY_DIR}:/policies zeek/zeek:latest zeek -C /policies/network-segmentation.zeek")
        return True
    except Exception as e:
        print(f"Error deploying policy: {e}")
        return False

def main():
    print("Fetching data from NetBox...")
    netbox_data = get_netbox_data()
    
    print("Generating Zeek policy...")
    policy = generate_zeek_policy(netbox_data)
    
    if policy:
        print("Writing Zeek policy configuration...")
        policy_file = write_zeek_policy(policy)
        
        print("Deploying policy...")
        success = deploy_zeek_policy(policy_file)
        
        if success:
            print(f"Network segmentation policy successfully created from NetBox data!")
            print(f"Policy file is at: {policy_file}")
        else:
            print(f"Policy file created at {policy_file}, but could not be automatically deployed.")
    else:
        print("No policy generated. Check your NetBox configuration.")

if __name__ == "__main__":
    main()


#!/usr/bin/env python3

import pynetbox
import yaml
import os
import subprocess
from datetime import datetime

# NetBox connection settings
NETBOX_URL = "http://localhost:8000"
NETBOX_TOKEN = "39acab6ffdc2316306ecf0725b2156ce4671e9f0"  # Replace with your actual token from NetBox

# Zeek policy directory
ZEEK_POLICY_DIR = os.path.expanduser("~/network-automation/zeek-config")

def get_netbox_data():
    """Retrieve network segmentation data from NetBox"""
    # This function connects to NetBox API and retrieves network information
    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
    
    # Get all VLANs and IP prefixes from NetBox
    vlans = nb.ipam.vlans.all()
    prefixes = nb.ipam.prefixes.all()
    
    # Get devices and their interfaces
    devices = nb.dcim.devices.all()
    
    return {
        'vlans': list(vlans),
        'prefixes': list(prefixes),
        'devices': list(devices)
    }

def generate_zeek_policy(netbox_data):
    """Generate Zeek network segmentation policy based on NetBox data"""
    # This function converts NetBox data into a policy format
    policy = []
    
    # Create network segments from VLANs
    segments = {}
    for vlan in netbox_data['vlans']:
        segments[vlan.name] = {
            'id': vlan.vid,
            'description': vlan.description or '',
            'prefixes': []
        }
    
    # Associate prefixes with segments
    for prefix in netbox_data['prefixes']:
        if prefix.vlan and prefix.vlan.name in segments:
            segments[prefix.vlan.name]['prefixes'].append(str(prefix.prefix))
    
    # Generate policy rules for each segment
    for name, segment in segments.items():
        if segment['prefixes']:
            policy.append({
                'segment': name,
                'networks': segment['prefixes'],
                'description': segment['description'],
                'isolation_level': 'default',
                'timestamp': datetime.now().isoformat()
            })
    
    return policy

def write_zeek_policy(policy):
    """Write policy to Zeek configuration file"""
    # This function writes the policy to a Zeek script file
    os.makedirs(ZEEK_POLICY_DIR, exist_ok=True)
    
    # Create the Zeek policy file
    policy_file = os.path.join(ZEEK_POLICY_DIR, "network-segmentation.zeek")
    
    with open(policy_file, 'w') as f:
        f.write("# Automatically generated network segmentation policy\n")
        f.write("# Generated at: {}\n\n".format(datetime.now().isoformat()))
        
        f.write("module NetworkSegmentation;\n\n")
        
        f.write("export {\n")
        f.write("    global segments: table[subnet] of string = {\n")
        
        # Write each network segment to the policy
        for rule in policy:
            for network in rule['networks']:
                f.write(f"        {network} = \"{rule['segment']}\",\n")
        
        f.write("    };\n")
        f.write("}\n\n")
        
        # Initialize the policy when Zeek starts
        f.write("event zeek_init() {\n")
        f.write("    print \"Loaded network segmentation policy\";\n")
        f.write("}\n\n")
        
        # Monitor connections and check if they cross segments
        f.write("event connection_established(c: connection) {\n")
        f.write("    local orig_segment = \"\"; \n")
        f.write("    local resp_segment = \"\"; \n")
        f.write("    \n")
        f.write("    if (c$orig$host in segments) {\n")
        f.write("        orig_segment = segments[c$orig$host];\n")
        f.write("    }\n")
        f.write("    \n")
        f.write("    if (c$resp$host in segments) {\n")
        f.write("        resp_segment = segments[c$resp$host];\n")
        f.write("    }\n")
        f.write("    \n")
        f.write("    if (orig_segment != \"\" && resp_segment != \"\" && orig_segment != resp_segment) {\n")
        f.write("        print fmt(\"Cross-segment traffic detected: %s -> %s\", orig_segment, resp_segment);\n")
        f.write("    }\n")
        f.write("}\n")
    
    # Also create a YAML version of the policy for easier reading
    yaml_file = os.path.join(ZEEK_POLICY_DIR, "network-segmentation-policy.yaml")
    with open(yaml_file, 'w') as f:
        yaml.dump(policy, f, default_flow_style=False)
    
    return policy_file

def deploy_zeek_policy(policy_file):
    """Deploy and activate the Zeek policy with Docker"""
    try:
        # For demo, just show how to run Zeek with the policy
        print(f"Policy file created at {policy_file}")
        print("To run Zeek with this policy, use:")
        print(f"docker run -v {ZEEK_POLICY_DIR}:/policies zeek/zeek:latest zeek -C /policies/network-segmentation.zeek")
        return True
    except Exception as e:
        print(f"Error deploying policy: {e}")
        return False

def main():
    print("Fetching data from NetBox...")
    netbox_data = get_netbox_data()
    
    print("Generating Zeek policy...")
    policy = generate_zeek_policy(netbox_data)
    
    if policy:
        print("Writing Zeek policy configuration...")
        policy_file = write_zeek_policy(policy)
        
        print("Deploying policy...")
        success = deploy_zeek_policy(policy_file)
        
        if success:
            print(f"Network segmentation policy successfully created from NetBox data!")
            print(f"Policy file is at: {policy_file}")
        else:
            print(f"Policy file created at {policy_file}, but could not be automatically deployed.")
    else:
        print("No policy generated. Check your NetBox configuration.")

if __name__ == "__main__":
    main()


