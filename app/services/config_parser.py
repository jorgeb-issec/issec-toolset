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
                'vdoms': [],
                'addresses': [],
                'services': [],
                'service_groups': [],
                'policies': []
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
            # timezone = re.search(r'set timezone "([^"]+)"', g_text)
            # if timezone: data['config_data']['system']['timezone'] = timezone.group(1)
            
            # admin_timeout = re.search(r'set admintimeout (\d+)', g_text)
            # if admin_timeout: data['config_data']['system']['admintimeout'] = admin_timeout.group(1)
            
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
        # Handle nested blocks (config ipv6...end) by finding the LAST 'end' at the correct indentation
        # or by finding the block that ends with 'end' at the start of a line (not indented)
        
        # Find all interface blocks using 'edit' and 'next' as delimiters
        # First, find the entire 'config system interface' section
        # Use a regex that matches 'config system interface' followed by content until a standalone 'end'
        interface_block_match = re.search(r'config system interface\s*\n(.*?)(?:^end$|\nend\n)', content, re.DOTALL | re.MULTILINE)
        if interface_block_match:
            intf_text = interface_block_match.group(1)
            
            # Split by 'edit ' - handles both quoted ("port1") and unquoted (port1) names
            # Pattern: edit "name" or edit name
            edits = re.split(r'\n\s*edit\s+', intf_text)
            for edit in edits[1:]: # Skip preamble
                # Extract interface name - handle both "quoted" and unquoted names
                if edit.startswith('"'):
                    # Quoted name: edit "port1"
                    end_quote_idx = edit.find('"', 1)
                    if end_quote_idx == -1: continue
                    name = edit[1:end_quote_idx]
                    block_content = edit[end_quote_idx+1:]
                else:
                    # Unquoted name: edit port1
                    end_name_match = re.match(r'(\S+)', edit)
                    if not end_name_match: continue
                    name = end_name_match.group(1)
                    block_content = edit[len(name):]
                
                # Extract params
                ip_match = re.search(r'set ip (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', block_content)
                vdom_match = re.search(r'set vdom "([^"]+)"', block_content)
                status_match = re.search(r'set status (\w+)', block_content)
                type_match = re.search(r'set type (\w+)', block_content)
                alias_match = re.search(r'set alias "([^"]+)"', block_content)
                role_match = re.search(r'set role (\w+)', block_content)
                vlanid_match = re.search(r'set vlanid (\d+)', block_content)
                allowaccess_match = re.search(r'set allowaccess ([^\n]+)', block_content)
                
                # Determine interface type with improved detection
                if type_match:
                    intf_type = type_match.group(1)
                elif 'vdom-link' in name:
                    # vdom-link interfaces should be identified by name
                    intf_type = 'vdom-link'
                elif vlanid_match:
                    # Has vlan_id but no explicit type - it's a VLAN
                    intf_type = 'vlan'
                else:
                    intf_type = 'physical'
                
                intf_info = {
                    'name': name,
                    'ip': f"{ip_match.group(1)}/{ip_match.group(2)}" if ip_match else "0.0.0.0/0.0.0.0",
                    'vdom': vdom_match.group(1) if vdom_match else "root",
                    'status': status_match.group(1) if status_match else "up", # Default is up usually
                    'type': intf_type,
                    'alias': alias_match.group(1) if alias_match else "",
                    'role': role_match.group(1) if role_match else "undefined",
                    'vlan_id': int(vlanid_match.group(1)) if vlanid_match else None,
                    'allowaccess': allowaccess_match.group(1).strip() if allowaccess_match else ""
                }
                data['config_data']['interfaces'].append(intf_info)

        # 6. Parse Objects & Policies by VDOM Context
        # We split by 'config vdom' sections to ensure objects are associated with correct VDOM.
        
        vdom_sections = re.split(r'config vdom', content)
        
        if len(vdom_sections) > 1: # VDOMs present
            for section in vdom_sections[1:]: # Skip preamble
                # Extract vdom name
                vdom_name_match = re.match(r'\s*edit\s+(?:(["\'])([^"\']+)\1|(\S+))', section)
                if not vdom_name_match: continue
                current_vdom = vdom_name_match.group(2) if vdom_name_match.group(2) else vdom_name_match.group(3)
                
                # Parse objects in this section
                ConfigParserService._parse_vdom_objects(section, current_vdom, data)
        else:
             # No VDOM structure found, parse entirely as root
             ConfigParserService._parse_vdom_objects(content, 'root', data)

        return data

    @staticmethod
    def _parse_vdom_objects(content, vdom, data):
        """Helper to parse all firewall objects and policies within a given VDOM/Context"""
        import re
        
        # --- Addresses ---
        addr_block_match = re.search(r'config firewall address\s*\n(.*?)(?:^end$|\nend\n)', content, re.DOTALL | re.MULTILINE)
        if addr_block_match:
            addr_text = addr_block_match.group(1)
            edits = re.split(r'\n\s*edit\s+', addr_text)
            for edit in edits[1:]:
                # Extract name
                if edit.startswith('"'):
                    end_quote = edit.find('"', 1)
                    name = edit[1:end_quote]
                    block = edit[end_quote+1:]
                else:
                    name_parts = edit.split(None, 1)
                    name = name_parts[0]
                    block = name_parts[1] if len(name_parts) > 1 else ""

                type_match = re.search(r'set type (\w+)', block)
                subnet_match = re.search(r'set subnet (\S+ \S+)', block)
                start_ip_match = re.search(r'set start-ip (\S+)', block)
                end_ip_match = re.search(r'set end-ip (\S+)', block)
                fqdn_match = re.search(r'set fqdn "([^"]+)"', block)
                country_match = re.search(r'set country "([^"]+)"', block)
                comment_match = re.search(r'set comment "([^"]+)"', block)
                
                addr_info = {
                    'name': name,
                    'vdom': vdom,
                    'type': type_match.group(1) if type_match else 'ipmask', 
                    'subnet': subnet_match.group(1) if subnet_match else None,
                    'start_ip': start_ip_match.group(1) if start_ip_match else None,
                    'end_ip': end_ip_match.group(1) if end_ip_match else None,
                    'fqdn': fqdn_match.group(1) if fqdn_match else None,
                    'country': country_match.group(1) if country_match else None,
                    'comments': comment_match.group(1) if comment_match else None,
                    'members': None, 
                    'raw_config': block.strip()
                }
                data['config_data']['addresses'].append(addr_info)

        # --- Address Groups ---
        addr_grp_match = re.search(r'config firewall addrgrp\s*\n(.*?)(?:^end$|\nend\n)', content, re.DOTALL | re.MULTILINE)
        if addr_grp_match:
            grp_text = addr_grp_match.group(1)
            edits = re.split(r'\n\s*edit\s+', grp_text)
            for edit in edits[1:]:
                if edit.startswith('"'):
                    end_quote = edit.find('"', 1)
                    name = edit[1:end_quote]
                    block = edit[end_quote+1:]
                else:
                    name_parts = edit.split(None, 1)
                    name = name_parts[0]
                    block = name_parts[1] if len(name_parts) > 1 else ""

                member_match = re.search(r'set member (.+)', block)
                members = []
                if member_match:
                    raw_members = member_match.group(1)
                    members = [m.strip('"') for m in re.findall(r'"[^"]*"|[^\s"]+', raw_members)]

                grp_info = {
                    'name': name,
                    'vdom': vdom,
                    'type': 'group',
                    'subnet': None,
                    'members': members,
                    'comments': None,
                    'raw_config': block.strip(),
                    # Add remaining fields as None to match schema
                    'start_ip': None, 'end_ip': None, 'fqdn': None, 'country': None
                }
                data['config_data']['addresses'].append(grp_info)

        # --- Services (Custom) ---
        svc_block_match = re.search(r'config firewall service custom\s*\n(.*?)(?:^end$|\nend\n)', content, re.DOTALL | re.MULTILINE)
        if svc_block_match:
            svc_text = svc_block_match.group(1)
            edits = re.split(r'\n\s*edit\s+', svc_text)
            for edit in edits[1:]:
                if edit.startswith('"'):
                    end_quote = edit.find('"', 1)
                    name = edit[1:end_quote]
                    block = edit[end_quote+1:]
                else:
                    name_parts = edit.split(None, 1)
                    name = name_parts[0]
                    block = name_parts[1] if len(name_parts) > 1 else ""

                protocol_match = re.search(r'set protocol (TCP/UDP/SCTP|ICMP|IP)', block)
                tcp_port_match = re.search(r'set tcp-portrange ([\d\-]+)', block)
                udp_port_match = re.search(r'set udp-portrange ([\d\-]+)', block)
                category_match = re.search(r'set category "([^"]+)"', block)
                comment_match = re.search(r'set comment "([^"]+)"', block)

                svc_info = {
                    'name': name,
                    'vdom': vdom,
                    'protocol': protocol_match.group(1) if protocol_match else 'TCP/UDP/SCTP',
                    'tcp_portrange': tcp_port_match.group(1) if tcp_port_match else None,
                    'udp_portrange': udp_port_match.group(1) if udp_port_match else None,
                    'category': category_match.group(1) if category_match else None,
                    'comments': comment_match.group(1) if comment_match else None,
                    'is_group': False
                }
                data['config_data']['services'].append(svc_info)

        # --- Service Groups ---
        grp_block_match = re.search(r'config firewall service group\s*\n(.*?)(?:^end$|\nend\n)', content, re.DOTALL | re.MULTILINE)
        if grp_block_match:
            grp_text = grp_block_match.group(1)
            edits = re.split(r'\n\s*edit\s+', grp_text)
            for edit in edits[1:]:
                if edit.startswith('"'):
                    end_quote = edit.find('"', 1)
                    name = edit[1:end_quote]
                    block = edit[end_quote+1:]
                else:
                    name_parts = edit.split(None, 1)
                    name = name_parts[0]
                    block = name_parts[1] if len(name_parts) > 1 else ""

                member_match = re.search(r'set member (.+)', block)
                members = []
                if member_match:
                    raw_members = member_match.group(1)
                    members = [m.strip('"') for m in re.findall(r'"[^"]*"|[^\s"]+', raw_members)]

                grp_info = {
                    'name': name,
                    'vdom': vdom,
                    'members': members,
                    'is_group': True,
                    # Fill others
                    'protocol': None, 'tcp_portrange': None, 'udp_portrange': None,
                    'category': None, 'comments': None
                }
                data['config_data']['services'].append(grp_info)

        # --- Policies ---
        ConfigParserService._parse_policy_block(content, vdom, data)

    @staticmethod
    def _parse_policy_block(content, vdom, data):
        """Helper to parse a policy block within a specific context"""
        import re
        poly_block_match = re.search(r'config firewall policy\s*\n(.*?)(?:^end$|\nend\n)', content, re.DOTALL | re.MULTILINE)
        if not poly_block_match: return
        
        poly_text = poly_block_match.group(1)
        edits = re.split(r'\n\s*edit\s+', poly_text)
        
        for edit in edits[1:]:
            # Policy ID is the name
            pid_match = re.match(r'(\d+)', edit)
            if not pid_match: continue
            policy_id = pid_match.group(1)
            
            # Helper to extract list fields (srcaddr, dstaddr, service)
            # set srcaddr "all" "object2"
            def extract_list(field_name):
                match = re.search(f'set {field_name} (.+)', edit)
                if match:
                    # Clean up: "all" "Test Object" -> ['all', 'Test Object']
                    return [m.strip('"') for m in re.findall(r'"[^"]*"|[^\s"]+', match.group(1))]
                return []
                
            srcintf = extract_list('srcintf')
            dstintf = extract_list('dstintf')
            srcaddr = extract_list('srcaddr')
            dstaddr = extract_list('dstaddr')
            service = extract_list('service')
            
            action_match = re.search(r'set action (\w+)', edit)
            status_match = re.search(r'set status (\w+)', edit)
            uuid_match = re.search(r'set uuid ([\w\-]+)', edit)
            name_match = re.search(r'set name "([^"]+)"', edit)
            
            policy_info = {
                'id': policy_id,
                'vdom': vdom,
                'name': name_match.group(1) if name_match else f"Policy {policy_id}",
                'uuid': uuid_match.group(1) if uuid_match else None,
                'action': action_match.group(1) if action_match else 'deny',
                'status': status_match.group(1) if status_match else 'enable',
                'srcintf': srcintf,
                'dstintf': dstintf,
                'srcaddr': srcaddr,
                'dstaddr': dstaddr,
                'service': service,
                'raw_config': edit.strip()
            }
            data['config_data']['policies'].append(policy_info)
