import re

class ConfigParserService:
    @staticmethod
    def parse_config(content):
        """
        Parses a FortiGate configuration file content.
        Returns a dict with 'hostname', 'serial', and 'config_data'.
        """
        data = {
            'hostname': None,
            'serial': None,
            'config_data': {
                'system': {},
                'interfaces': [],
                'firmware': None,
                'vdoms': []
            }
        }
        
        # 1. Firmware Version (often in header)
        # #config-version=FG2H0G-7.4.8-FW-build2795-250523...
        version_match = re.search(r'#config-version=(\S+)', content)
        if version_match:
            data['config_data']['firmware'] = version_match.group(1)
            
        # 1b. VDOM Name (from header if specific VDOM config)
        # #global_vdom=0:vd_name=routing/routing
        vdom_header_match = re.search(r'vd_name=([^/]+)/(\S+)', content)
        if vdom_header_match:
             # usually "root/root" or "routing/routing"
             # group(1) might be vdom name, or group(2)? 
             # In "routing/routing", it seems to be name/uuid or name/alias. 
             # Let's take group(1) as name.
             data['vdom_name'] = vdom_header_match.group(1)
        else:
            data['vdom_name'] = None
            
        # 2. Hostname
        hostname_match = re.search(r'set hostname "([^"]+)"', content)
        if hostname_match:
            data['hostname'] = hostname_match.group(1)
        else:
            hostname_match_nq = re.search(r'set hostname (\S+)', content)
            if hostname_match_nq:
                 data['hostname'] = hostname_match_nq.group(1)
                 
        if not data['hostname']:
             data['hostname'] = "Unknown-Device"

        # 3. Serial Number
        # FortiOS configs may not include the device serial for security reasons.
        # Try multiple locations where it might appear:
        
        # 3a. Try to find in system global (rare, but possible)
        serial_match = re.search(r'set serial[- ]number\s+"?([A-Z0-9]+)"?', content, re.IGNORECASE)
        if serial_match:
            data['serial'] = serial_match.group(1)
        else:
            # 3b. Try to find in HA configuration
            ha_serial_match = re.search(r'set override\s+enable.*?set serial\s+"?([A-Z0-9]+)"?', content, re.DOTALL | re.IGNORECASE)
            if ha_serial_match:
                data['serial'] = ha_serial_match.group(1)
            else:
                # 3c. Serial not found in config - will need to be provided by user
                data['serial'] = None
 
        
        # 4. Config System Global
        # Extract basic global settings
        global_block = re.search(r'config system global(.*?)end', content, re.DOTALL)
        if global_block:
            g_text = global_block.group(1)
            timezone = re.search(r'set timezone "([^"]+)"', g_text)
            if timezone: data['config_data']['system']['timezone'] = timezone.group(1)
            
            admin_timeout = re.search(r'set admintimeout (\d+)', g_text)
            if admin_timeout: data['config_data']['system']['admintimeout'] = admin_timeout.group(1)
            
        # 4b. Extract VDOMs
        # config vdom
        #   edit root
        #   next
        #   edit routing
        #   next
        vdom_block_match = re.search(r'config vdom(.*?)(?:^end|\nend)', content, re.DOTALL | re.MULTILINE)
        if vdom_block_match:
            vdom_text = vdom_block_match.group(1)
            # Use regex to find all 'edit' statements
            # This regex handles both 'edit root' and 'edit "vdom name"'
            edit_matches = re.finditer(r'edit\s+(?:(["\'])([^"\']+)\1|(\S+))', vdom_text)
            for match in edit_matches:
                # Group 2 captures quoted names, Group 3 captures unquoted names
                vdom_name = match.group(2) if match.group(2) else match.group(3)
                if vdom_name and vdom_name not in data['config_data']['vdoms']:
                    data['config_data']['vdoms'].append(vdom_name)

        # 4c. Extract HA Configuration
        ha_block_match = re.search(r'config system ha(.*?)^end', content, re.DOTALL | re.MULTILINE)
        if ha_block_match:
            ha_text = ha_block_match.group(1)
            
            mode_match = re.search(r'set mode (\S+)', ha_text)
            group_name_match = re.search(r'set group-name "([^"]+)"', ha_text)
            group_id_match = re.search(r'set group-id (\d+)', ha_text)
            hbdev_match = re.search(r'set hbdev "([^"]+)"', ha_text)
            
            ha_mode = mode_match.group(1) if mode_match else 'standalone'
            
            data['config_data']['ha'] = {
                'mode': ha_mode,  # standalone, a-p (active-passive), a-a (active-active)
                'enabled': ha_mode != 'standalone',
                'group_name': group_name_match.group(1) if group_name_match else None,
                'group_id': int(group_id_match.group(1)) if group_id_match else None,
                'heartbeat_device': hbdev_match.group(1) if hbdev_match else None
            }
        else:
            data['config_data']['ha'] = {
                'mode': 'standalone',
                'enabled': False
            }

        # 5. Interfaces
        # Parse 'config system interface' ... 'end'
        # We need a robust parser for nested blocks. 
        # Simple regex for 'edit "name" ... next'
        
        interface_block_match = re.search(r'config system interface(.*?)end', content, re.DOTALL)
        if interface_block_match:
            intf_text = interface_block_match.group(1)
            # Split by 'edit '
            edits = intf_text.split('edit "')
            for edit in edits[1:]: # Skip preamble
                # Extract name "port1" ...
                end_quote_idx = edit.find('"')
                if end_quote_idx == -1: continue
                
                name = edit[:end_quote_idx]
                block_content = edit[end_quote_idx+1:]
                
                # Extract params
                ip_match = re.search(r'set ip (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', block_content)
                vdom_match = re.search(r'set vdom "([^"]+)"', block_content)
                status_match = re.search(r'set status (\w+)', block_content)
                type_match = re.search(r'set type (\w+)', block_content)
                alias_match = re.search(r'set alias "([^"]+)"', block_content)
                role_match = re.search(r'set role (\w+)', block_content)
                
                intf_info = {
                    'name': name,
                    'ip': f"{ip_match.group(1)}/{ip_match.group(2)}" if ip_match else "0.0.0.0/0.0.0.0",
                    'vdom': vdom_match.group(1) if vdom_match else "root",
                    'status': status_match.group(1) if status_match else "up", # Default is up usually
                    'type': type_match.group(1) if type_match else "physical",
                    'alias': alias_match.group(1) if alias_match else "",
                    'role': role_match.group(1) if role_match else "undefined"
                }
                data['config_data']['interfaces'].append(intf_info)

        return data
