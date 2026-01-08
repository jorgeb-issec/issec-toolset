# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

## [1.3.0] - 2026-01-08

### Agregado - Base de Datos
- **Interfaces**: Nueva tabla `interfaces` para almacenamiento normalizado de interfaces
- **Address Objects**: Nueva tabla `address_objects` para objetos de dirección FortiGate
- **Service Objects**: Nueva tabla `service_objects` para definiciones de servicios
- **VPN Tunnels**: Nueva tabla `vpn_tunnels` para seguimiento de túneles IPSec/SSL-VPN
- **Tablas de Mapeo N:M**: `policy_interface_mappings`, `policy_address_mappings`, `policy_service_mappings`
- **Alertas de Seguridad**: `allowed_access_alerts` y `server_exposures` para análisis de riesgos
- **Historial**: `interface_history` y `vdom_history` para auditoría

### Modificado
- `policies`: Agregado `vdom_id` FK para vincular con VDOMs
- `log_entries`: Agregado `vdom_id`, `src_intf_id`, `dst_intf_id` FKs
- `policy_history`: Agregado `vdom_id` FK

---

## [1.1b] - 2024-12-26

### Agregado
- **Historial de Cambios**: Filtro por tipo de cambio (Creado/Modificado/Eliminado)
- **Reportes**: Selector múltiple de VDOMs con opción "Todos"
- **Reportes Personalizados**: Filtros separados para Interface y Address (Origen/Destino)
- **Dashboard de Equipos**: Detección de modo HA desde archivos .conf
- **Dashboard de Equipos**: Botón "Actualizar Config" para refrescar datos
- **Dashboard de Equipos**: Títulos de sección para VDOMs e Interfaces

### Cambiado
- Filtro de duplicados ahora busca políticas con misma config en el **mismo VDOM**
- Agrupación visual de políticas duplicadas con colores alternados

### Corregido
- Columnas de tabla en Policy Explorer ya no se superponen
- Mensaje de confirmación de VDOM en importación de políticas

---

## [1.0b] - 2024-12-01

### Agregado
- Multi-tenancy con bases de datos segregadas
- Policy Explorer con filtros avanzados
- Generación de reportes PDF
- Auditoría de cambios en políticas
- Gestión de usuarios y roles
- Dashboard centralizado
