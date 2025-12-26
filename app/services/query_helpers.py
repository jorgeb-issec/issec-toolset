from app.models.policy import Policy
from sqlalchemy import or_, and_

def find_duplicate_policies(device_id, vdom, src_intf, dst_intf, src_addr, dst_addr, service, action):
    """
    Busca políticas que coincidan exactamente en los criterios clave.
    Útil para ver si una regla que queremos crear ya existe.
    """
    query = Policy.query.filter(
        Policy.device_id == device_id,
        Policy.vdom == vdom,
        Policy.src_intf == src_intf,
        Policy.dst_intf == dst_intf,
        Policy.src_addr == src_addr,
        Policy.dst_addr == dst_addr,
        Policy.service == service,
        Policy.action == action
    )
    return query.all()

def find_bad_practices(device_id=None, check_any_source=True, check_any_dest=True, check_any_service=False):
    """
    Busca reglas permisivas peligrosas (Any-Any).
    Usa ILIKE para buscar 'all', 'any' o '0.0.0.0/0' dentro de las listas convertidas a string.
    """
    query = Policy.query
    
    if device_id:
        query = query.filter(Policy.device_id == device_id)

    # Solo nos interesan las reglas que permiten tráfico
    query = query.filter(Policy.action == 'ACCEPT')

    conditions = []
    
    # Criterio: Origen es 'all' o 'any'
    if check_any_source:
        conditions.append(or_(
            Policy.src_addr.ilike('%all%'),
            Policy.src_addr.ilike('%any%'),
            Policy.src_addr.ilike('%0.0.0.0/0%')
        ))

    # Criterio: Destino es 'all' o 'any'
    if check_any_dest:
        conditions.append(or_(
            Policy.dst_addr.ilike('%all%'),
            Policy.dst_addr.ilike('%any%'),
            Policy.dst_addr.ilike('%0.0.0.0/0%')
        ))

    # Criterio: Servicio es 'ALL'
    if check_any_service:
        conditions.append(or_(
            Policy.service.ilike('%ALL%'),
            Policy.service.ilike('%ANY%')
        ))

    # Aplicar filtros (AND lógico entre las condiciones activadas)
    if conditions:
        for condition in conditions:
            query = query.filter(condition)
            
    return query.all()

def search_complex_policy(device_id, filters):
    """
    Búsqueda avanzada flexible.
    filters es un dict: {'nat': 'Enabled', 'src_intf': 'port1'}
    """
    query = Policy.query.filter(Policy.device_id == device_id)
    
    if filters.get('src_intf'):
        query = query.filter(Policy.src_intf.ilike(f"%{filters['src_intf']}%"))
        
    if filters.get('dst_intf'):
        query = query.filter(Policy.dst_intf.ilike(f"%{filters['dst_intf']}%"))
        
    if filters.get('src_addr'):
        query = query.filter(Policy.src_addr.ilike(f"%{filters['src_addr']}%"))
        
    if filters.get('dst_addr'):
        query = query.filter(Policy.dst_addr.ilike(f"%{filters['dst_addr']}%"))

    if filters.get('nat'):
        # NAT puede ser booleano o string
        query = query.filter(Policy.nat == filters['nat'])

    return query.all()