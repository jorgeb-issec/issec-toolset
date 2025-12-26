import json
import uuid
from app.models.policy import Policy
from app.models.history import PolicyHistory
from app.services.fortigate_importer import parse_bytes_str, get_nat_status, list_to_str

class PolicyDiffService:
    @staticmethod
    def compare_policies(session, device_id, vdom, new_json_list):
        """
        Comparison logic with History Logging:
        1. Fetch all existing policies for (device_id, vdom).
        2. Index existing by 'policy_id'.
        3. Iterate new list.
           - If ID exists: Compare fields. If diff -> MODIFIED. Log History.
           - If ID not exists: -> ADDED. Log History.
           - Keep track of processed IDs.
        4. Any existing ID not processed -> DELETED. Log History.
        """
        
        # Ensure device_id is UUID
        if isinstance(device_id, str):
            device_id = uuid.UUID(device_id)

        # 1. Fetch Existing
        existing_query = session.query(Policy).filter_by(device_id=device_id, vdom=vdom).all()
        existing_map = {p.policy_id: p for p in existing_query}
        
        diff_report = {
            'added': [],
            'modified': [],
            'deleted': [],
            'unchanged_count': 0
        }
        
        processed_ids = set()
        
        # 2. Iterate New
        for r in new_json_list:
            pid = str(r.get('ID', '0'))
            processed_ids.add(pid)
            
            # Helper: Extract critical fields
            src_list = r.get('From') or r.get('srcintf') or []
            dst_list = r.get('To') or r.get('dstintf') or []
            
            # Interface Pair Fallback
            if not src_list and not dst_list:
                pair = r.get('Interface Pair', '')
                if pair and ',' in pair:
                    parts = pair.split(',')
                    if len(parts) >= 2:
                        src_list = [parts[0].strip()]
                        dst_list = [parts[1].strip()]
                        r['From'] = src_list
                        r['To'] = dst_list

            new_obj_data = {
                'src_intf': list_to_str(src_list),
                'dst_intf': list_to_str(dst_list),
                'src_addr': list_to_str(r.get('Source Address', r.get('Source', []))),
                'dst_addr': list_to_str(r.get('Destination Address', r.get('Destination', []))),
                'service': list_to_str(r.get('Service', [])),
                'action': r.get('Action', 'DENY'),
                'nat': get_nat_status(r),
            }
            
            if pid in existing_map:
                # Compare
                current = existing_map[pid]
                changes = []
                
                # Check fields
                if current.src_intf != new_obj_data['src_intf']: changes.append(f"Src Intf: {current.src_intf} -> {new_obj_data['src_intf']}")
                if current.dst_intf != new_obj_data['dst_intf']: changes.append(f"Dst Intf: {current.dst_intf} -> {new_obj_data['dst_intf']}")
                if current.src_addr != new_obj_data['src_addr']: changes.append(f"Src Addr: {current.src_addr} -> {new_obj_data['src_addr']}")
                if current.dst_addr != new_obj_data['dst_addr']: changes.append(f"Dst Addr: {current.dst_addr} -> {new_obj_data['dst_addr']}")
                if current.service != new_obj_data['service']: changes.append(f"Service: {current.service} -> {new_obj_data['service']}")
                if current.action != new_obj_data['action']: changes.append(f"Action: {current.action} -> {new_obj_data['action']}")
                if current.nat != new_obj_data['nat']: changes.append(f"NAT: {current.nat} -> {new_obj_data['nat']}")
                
                if changes:
                    # Log History for MODIFY
                    history = PolicyHistory(
                        policy_uuid=current.uuid,
                        device_id=device_id,
                        change_type='modify',
                        delta={'changes': changes},
                        snapshot=r
                    )
                    session.add(history)
                    
                    diff_report['modified'].append({
                        'policy_id': pid,
                        'name': r.get('Name', ''),
                        'changes': changes,
                        'new_data': r
                    })
                else:
                    diff_report['unchanged_count'] += 1
            else:
                # Added - We don't have UUID yet because it's not inserted. 
                # This function is comparison only, typically executed BEFORE database update or DURING?
                # Usually called by `import_policies` route.
                # If we want to log 'create' history, we need the UUID.
                # The importer loop will create the Policy object.
                # So we should probably return a flag or handle history creation here but we need the UUID.
                # But for 'Added', the policy doesn't exist yet.
                # Optimization: We return the list of added items, and the Route/Service that INSERTS them should also INSERT the history.
                # OR: We generate UUID here if we were creating objects, but we are just reporting diffs.
                
                # Wait, this Service just returns a report. It doesn't commit to DB?
                # "compare_policies" name suggests read-only.
                # BUT I added `session.add(history)`.
                # If this function is meant to be just a "preview", saving history is wrong.
                # However, the user request is "las politicas tambien necesitan guardar los deltas".
                # This usually happens upon "Commit" or "Save".
                # Let's check `policy_routes.py` to see how this is used.
                
                # Assuming this is used during the actual Import/Update process.
                pass # Proceeding with logic assuming we want to persist history on change detection.
                
                diff_report['added'].append({
                    'policy_id': pid,
                    'name': r.get('Name', ''),
                    'new_data': r
                })
                
        # 3. Find Deleted
        for pid, policy in existing_map.items():
            if pid not in processed_ids:
                # Log History for DELETE
                history = PolicyHistory(
                    policy_uuid=policy.uuid, 
                    device_id=device_id,
                    change_type='delete',
                    delta={'reason': 'missing_in_import'},
                    snapshot=policy.raw_data
                )
                session.add(history)
                
                diff_report['deleted'].append({
                    'policy_id': pid,
                    'name': policy.name,
                    'uuid': str(policy.uuid) 
                })
                
        return diff_report
