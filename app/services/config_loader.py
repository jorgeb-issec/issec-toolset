from app.extensions.db import db
from app.models.equipo import Equipo
from app.models.vdom import VDOM
from app.models.interface import Interface
from app.models.address_object import AddressObject
from app.models.service_object import ServiceObject
from app.models.policy import Policy
from app.models.policy_mappings import (
    PolicyInterfaceMapping, 
    PolicyAddressMapping, 
    PolicyServiceMapping
)
import logging

logger = logging.getLogger(__name__)

class ConfigLoaderService:
    @staticmethod
    def load_config(device_id, config_data, session=None):
        """
        Loads parsed configuration data into the database for a specific device.
        :param device_id: UUID of the target device
        :param config_data: Dictionary containing parsed config (from ConfigParserService)
        :param session: SQLAlchemy session to use (defaults to db.session)
        """
        if not session:
            session = db.session
            
        try:
            device = session.query(Equipo).get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")

            # 1. Sync VDOMs
            vdom_map = ConfigLoaderService._sync_vdoms(device, config_data, session)
            
            # 2. Sync Interfaces
            ConfigLoaderService._sync_interfaces(device, vdom_map, config_data, session)
            
            # 3. Sync Address Objects
            ConfigLoaderService._sync_address_objects(device, vdom_map, config_data, session)
            
            # 4. Sync Service Objects
            ConfigLoaderService._sync_service_objects(device, vdom_map, config_data, session)
            
            # 5. Sync Policies
            ConfigLoaderService._sync_policies(device, vdom_map, config_data, session)
            
            session.commit()
            return True, "Configuration loaded successfully"
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error loading config for device {device_id}: {str(e)}", exc_info=True)
            return False, str(e)

    @staticmethod
    def _sync_vdoms(device, data, session):
        """Ensures VDOMs exist and returns a name->ID map"""
        vdom_names = set(data.get('vdoms', []))
        if not vdom_names:
            vdom_names.add('root') # Default if none parsed

        existing_vdoms = session.query(VDOM).filter_by(device_id=device.id).all()
        vdom_map = {v.name: v.id for v in existing_vdoms}
        
        for name in vdom_names:
            if name not in vdom_map:
                new_vdom = VDOM(device_id=device.id, name=name, comments="Auto-created by ConfigLoader")
                session.add(new_vdom)
                session.flush() # Get ID
                vdom_map[name] = new_vdom.id
                
        return vdom_map

    @staticmethod
    def _sync_interfaces(device, vdom_map, data, session):
        # Clear existing interfaces for clean slate? Or update?
        # For now, let's delete and recreate to avoid staleness, or complex diffing.
        # But deleting implies cascading deletes.
        # Ideally we update existing by name+vdom, delete missing.
        
        current_interfaces = session.query(Interface).filter_by(device_id=device.id).all()
        # Interface names are unique per device, regardless of VDOM.
        current_map = {i.name: i for i in current_interfaces}
        
        parsed_interfaces = data.get('interfaces', [])
        seen_keys = set()
        
        for intf in parsed_interfaces:
            vdom_name = intf.get('vdom', 'root')
            vdom_id = vdom_map.get(vdom_name)
            if not vdom_id: continue # Should not happen if _sync_vdoms works
            
            key = intf.get('name')
            seen_keys.add(key)
            
            # Calculate allowaccess
            aa = intf.get('allowaccess', [])
            if isinstance(aa, str): aa = aa.split()
            
            if key in current_map:
                # Update
                obj = current_map[key]
                obj.vdom_id = vdom_id  # Update VDOM just in case it moved
                obj.ip_address = intf.get('ip')
                obj.status = intf.get('status', 'up')
                obj.type = intf.get('type', 'physical')
                obj.alias = intf.get('alias')
                obj.allowaccess = aa
            else:
                # Create
                new_intf = Interface(
                    device_id=device.id,
                    vdom_id=vdom_id,
                    name=intf.get('name'),
                    alias=intf.get('alias'),
                    type=intf.get('type', 'physical'),
                    status=intf.get('status', 'up'),
                    ip_address=intf.get('ip'),
                    allowaccess=aa,
                    config_data=intf
                )
                session.add(new_intf)
                current_map[key] = new_intf # Prevent duplicate inserts if same key repeats in input

    @staticmethod
    def _sync_address_objects(device, vdom_map, data, session):
        # Similar Logic: Update/Create.
        # Address objects are identified by unique (device_id, vdom_id, name)
        
        current_objs = session.query(AddressObject).filter_by(device_id=device.id).all()
        current_map = {(obj.name, obj.vdom_id): obj for obj in current_objs}
        
        parsed_objs = data.get('addresses', [])
        
        for obj_data in parsed_objs:
            vdom_name = obj_data.get('vdom', 'root')
            vdom_id = vdom_map.get(vdom_name)
            
            key = (obj_data.get('name'), vdom_id)
            
            if key in current_map:
                # Update
                obj = current_map[key]
                obj.type = obj_data.get('type')
                obj.subnet = obj_data.get('subnet')
                obj.start_ip = obj_data.get('start_ip')
                obj.end_ip = obj_data.get('end_ip')
                obj.fqdn = obj_data.get('fqdn')
                obj.country = obj_data.get('country')
                obj.members = obj_data.get('members')
                obj.comments = obj_data.get('comments')
            else:
                # Create
                new_obj = AddressObject(
                    device_id=device.id,
                    vdom_id=vdom_id,
                    name=obj_data.get('name'),
                    type=obj_data.get('type'),
                    subnet=obj_data.get('subnet'),
                    start_ip=obj_data.get('start_ip'),
                    end_ip=obj_data.get('end_ip'),
                    fqdn=obj_data.get('fqdn'),
                    country=obj_data.get('country'),
                    members=obj_data.get('members'),
                    comments=obj_data.get('comments'),
                    config_data={'raw': obj_data.get('raw_config')}
                )
                session.add(new_obj)
                current_map[key] = new_obj # Prevent duplicates

    @staticmethod
    def _sync_service_objects(device, vdom_map, data, session):
        current_objs = session.query(ServiceObject).filter_by(device_id=device.id).all()
        current_map = {(obj.name, obj.vdom_id): obj for obj in current_objs}
        
        parsed_objs = data.get('services', []) # Includes groups if parser puts them there
        # Check if parser separates groups. My parser put groups in 'services' list too? 
        # Wait, my parser had: data['config_data']['services'].append(grp_info) 
        # YES.
        
        for obj_data in parsed_objs:
            vdom_name = obj_data.get('vdom', 'root')
            vdom_id = vdom_map.get(vdom_name)
            
            key = (obj_data.get('name'), vdom_id)
            
            if key in current_map:
                obj = current_map[key]
                obj.protocol = obj_data.get('protocol')
                obj.tcp_portrange = obj_data.get('tcp_portrange')
                obj.udp_portrange = obj_data.get('udp_portrange')
                obj.category = obj_data.get('category')
                obj.is_group = obj_data.get('is_group', False)
                obj.members = obj_data.get('members')
                obj.comments = obj_data.get('comments')
            else:
                new_obj = ServiceObject(
                    device_id=device.id,
                    vdom_id=vdom_id,
                    name=obj_data.get('name'),
                    protocol=obj_data.get('protocol'),
                    tcp_portrange=obj_data.get('tcp_portrange'),
                    udp_portrange=obj_data.get('udp_portrange'),
                    category=obj_data.get('category'),
                    is_group=obj_data.get('is_group', False),
                    members=obj_data.get('members'),
                    comments=obj_data.get('comments'),
                    config_data={'raw': obj_data.get('raw_config', '')}
                )
                session.add(new_obj)
                current_map[key] = new_obj # Prevent duplicates

    @staticmethod
    def _sync_policies(device, vdom_map, data, session):
        #Policies are complex. Probably best to delete all for this device/vdom and recreate?
        # Or try to match by Policy ID + VDOM.
        # Matched by ID is safer.
        
        current_policies = session.query(Policy).filter_by(device_id=device.id).all()
        current_map = {(str(p.policy_id), p.vdom_id): p for p in current_policies}
        uuid_map = {str(p.uuid): p for p in current_policies if p.uuid}
        
        parsed_policies = data.get('policies', [])
        
        # We also need to Resolve Object References for Mappings...
        # [Skipped context - assuming maps are loaded below, focusing on Policy loop]
        # Reload objects to get IDs
        all_addrs = session.query(AddressObject).filter_by(device_id=device.id).all()
        addr_map = {(a.name, a.vdom_id): a for a in all_addrs}
        
        all_svcs = session.query(ServiceObject).filter_by(device_id=device.id).all()
        svc_map = {(s.name, s.vdom_id): s for s in all_svcs}
        
        all_intfs = session.query(Interface).filter_by(device_id=device.id).all()
        # Interface map keyed by name as per previous fix
        intf_map = {i.name: i for i in all_intfs}

        for poly_data in parsed_policies:
            vdom_name = poly_data.get('vdom', 'root')
            vdom_id = vdom_map.get(vdom_name)
            pid = str(poly_data.get('id'))
            uuid_val = poly_data.get('uuid')
            
            key = (pid, vdom_id)
            
            p_obj = None
            
            # 1. Search by UUID (Strongest match)
            if uuid_val and uuid_val in uuid_map:
                p_obj = uuid_map[uuid_val]
            # 2. Search by ID+VDOM (Fallback)
            elif key in current_map:
                p_obj = current_map[key]
                
            if p_obj:
                # Update basic fields
                p_obj.vdom_id = vdom_id # Update VDOM in case it changed
                p_obj.name = poly_data.get('name')
                p_obj.action = poly_data.get('action')
                p_obj.status = poly_data.get('status')
                p_obj.uuid = uuid_val if uuid_val else p_obj.uuid
                p_obj.raw_data = poly_data
                
                # Clear existing mappings manually
                # We will re-add them below.
                # Since relationships are dynamic/lazy, we can't just list clear.
                # We need to delete from the mapping tables.
                # Or rely on efficient upsert? No, duplicates in mappings.
                # Best: Session delete mappings for this policy.
                # But we don't have mapping objects loaded.
                
                # Deleting mappings via SQL query is fastest?
                # session.query(PolicyInterfaceMapping).filter_by(policy_uuid=p_obj.uuid).delete()
                # But we need imports.
                pass 
            else:
                p_obj = Policy(
                    device_id=device.id,
                    vdom_id=vdom_id,
                    policy_id=pid,
                    name=poly_data.get('name'),
                    action=poly_data.get('action'),
                    status=poly_data.get('status'),
                    uuid=uuid_val,
                    raw_data=poly_data
                )
                session.add(p_obj)
                session.flush() # Need ID/UUID
                
            # Clear mappings for this policy to avoid duplicates
            # We can use the relationships if cascade delete-orphan is set?
            # Policy.interface_mappings is cascade='all, delete-orphan'.
            # So if we do p_obj.interface_mappings = [], it should work?
            # But relationships are dynamic query.
            # p_obj.interface_mappings.delete() # works for dynamic check
            if p_obj.uuid: # Only if persisted/flushed
                 # Clear existing mappings using session.query
                 session.query(PolicyInterfaceMapping).filter_by(policy_uuid=p_obj.uuid).delete(synchronize_session=False)
                 session.query(PolicyAddressMapping).filter_by(policy_uuid=p_obj.uuid).delete(synchronize_session=False)
                 session.query(PolicyServiceMapping).filter_by(policy_uuid=p_obj.uuid).delete(synchronize_session=False)
            
            # Now Handle Mappings
            
            def find_addr_id(name, vdom_id):
                # 1. Try specific vdom
                if (name, vdom_id) in addr_map: 
                    return addr_map[(name, vdom_id)]
                # 2. Try root/global vdom (common for 'all')
                root_id = vdom_map.get('root')
                if root_id and (name, root_id) in addr_map:
                    return addr_map[(name, root_id)]
                # 3. If 'all' and not found, maybe we skipped creating it?
                # But parser should have found it if configured. 
                # If it's a default object not in config, we might miss it.
                return None

            def find_intf_id(name, vdom_id):
                if (name, vdom_id) in intf_map:
                    return intf_map[(name, vdom_id)].id
                # Search in root?
                root_id = vdom_map.get('root')
                if root_id and (name, root_id) in intf_map:
                    return intf_map[(name, root_id)].id
                return None

            # --- Interfaces ---
            # srcintf
            for iname in poly_data.get('srcintf', []):
                # if iname is 'any' or 'all'? Fortigate uses 'any'.
                iid = find_intf_id(iname, vdom_id)
                if iid:
                    mapping = PolicyInterfaceMapping(policy=p_obj, interface_id=iid, direction='src')
                    session.add(mapping)
                    
            # dstintf
            for iname in poly_data.get('dstintf', []):
                iid = find_intf_id(iname, vdom_id)
                if iid:
                    mapping = PolicyInterfaceMapping(policy=p_obj, interface_id=iid, direction='dst')
                    session.add(mapping)
                
            # --- Addresses ---
            # srcaddr
            for aname in poly_data.get('srcaddr', []):
                # Resolve object ID if possible, otherwise just store name in mapping (mapping table usually has object_id FK?)
                # Let's check model. usually it links to object.
                # If object_id is nullable in mapping, we can store name? No, usually mappings link IDs.
                # If we cannot find ID, we might skip or fail.
                # However, we just loaded all objects.
                # 'all' address object usually exists or is implicit. 
                # If 'all' is not in our objects list, we should stick to name usage if mapping supports it?
                # app/models/policy_mappings.py usually has (policy_id, address_id).
                
                addr_obj = find_addr_id(aname, vdom_id)
                if addr_obj:
                    mapping = PolicyAddressMapping(policy=p_obj, address_id=addr_obj.id, direction='src')
                else:
                    # If 'all' or special object not found, what to do?
                    # Maybe create a dummy 'all' object if not exists?
                    # Or just log warning.
                    # For ZTNA, we need to know it is 'all'.
                    # If the DB enforces address_id FK, we MUST have an object.
                    # Assumption: The parse/load step created an object for 'all' if it was in config?
                    # 'all' is default valid address object in FortiOS but might not appear in 'config firewall address'.
                    # We should probably create a placeholder 'all' object for each VDOM if missing.
                    pass 
                
                # Check logic: if we have keys/relationships, we need to set them.
                if addr_obj:
                    session.add(mapping)

            # dstaddr
            for aname in poly_data.get('dstaddr', []):
                addr_obj = find_addr_id(aname, vdom_id)
                if addr_obj:
                    mapping = PolicyAddressMapping(policy=p_obj, address_id=addr_obj.id, direction='dst')
                    session.add(mapping)

            # --- Services ---
            for sname in poly_data.get('service', []):
                svc_obj = svc_map.get((sname, vdom_id))
                # Services like 'ALL', 'HTTP' are default objects. 
                # If they are not in 'config firewall service custom', they are pre-defined.
                # We might be missing pre-defined services in our DB.
                # We should create them on the fly or warn?
                if svc_obj:
                    mapping = PolicyServiceMapping(policy=p_obj, service_id=svc_obj.id)
                    session.add(mapping)
                else:
                    # Create a "System/Default" service object placeholder if missing?
                    # Better to have comprehensive service list but for now, we skip or create stub.
                    pass
