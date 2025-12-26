# ISSEC Toolset - P.U.N.K.L.I.T.H. 1.1b

**Protocolos Unificados de Negación, Kontrol y Lógica de Intercepción de Tráfico Hostil**

Una plataforma multi-tenant diseñada para la gestión, auditoría y análisis de políticas de seguridad en firewalls FortiGate.

## 🚀 Instalación Rápida

```bash
git clone https://github.com/your-org/issec-toolset.git
cd issec-toolset
./scripts/setup.sh
flask run
```

Para instalación detallada: [docs/INSTALL.md](docs/INSTALL.md)

---

## ✨ Características Principales

### 🏢 Multi-Tenancy (Multi-Empresa)
- Gestión centralizada de múltiples clientes (Tenants)
- Bases de datos segregadas para cada empresa
- **Role-Based Access Control (RBAC)** con roles Globales y por Empresa

### 🛡️ Policy Explorer
- Visualización avanzada de políticas de firewall
- **Filtros Gránulares**: Por VDOM, Interfaces, IPs, Servicios, Acción
- **Auditoría de Cambios**: Detección de Deltas (Nuevas, Modificadas, Eliminadas)
- **Generación de Scripts**: Creación automática de scripts Disable/Delete
- **Detección de Duplicados**: Identifica políticas redundantes

### 📊 Reportes y Dashboard
- Dashboard centralizado con métricas clave
- Generación de reportes PDF con marca blanca
- Filtros avanzados por VDOM, Interface, Address
- Exportación a CSV/Excel

### ⚙️ Administración de Equipos
- Gestión de dispositivos FortiGate por sitio
- Importación de configuraciones (.conf)
- Visualización de VDOMs e interfaces
- Detección de modo HA (Alta Disponibilidad)

---

## 📋 Requisitos

- Python 3.8+
- PostgreSQL 12+
- Navegador moderno (Chrome, Firefox, Edge)

---

## 🔐 Credenciales por Defecto

```
Email: admin@issec.com
Password: admin123
```

⚠️ **Cambiar inmediatamente después del primer login**

---

## 📁 Estructura del Proyecto

```
issec-toolset/
├── app/                 # Aplicación Flask
├── scripts/             # Scripts de utilidad
│   ├── setup.sh         # Instalación automática
│   └── legacy/          # Scripts de migración
├── migrations/          # Alembic migrations
├── docs/                # Documentación
└── tests/               # Tests
```

---

## 📄 Licencia

Propietario - ISSEC Security © 2024

---

## 🔄 Changelog

Ver [CHANGELOG.md](CHANGELOG.md)