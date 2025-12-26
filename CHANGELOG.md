# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

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
