# Guía de Instalación - ISSEC Toolset

## Requisitos Previos

- **Python 3.8+**
- **PostgreSQL 12+**
- **pip** (gestor de paquetes de Python)
- **Git**

## Instalación Rápida

```bash
# 1. Clonar repositorio
git clone https://github.com/your-org/issec-toolset.git
cd issec-toolset

# 2. Ejecutar script de instalación
./scripts/setup.sh
```

## Instalación Manual

### 1. Crear entorno virtual

```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 3. Configurar base de datos PostgreSQL

```bash
# Crear usuario y base de datos
sudo -u postgres psql
postgres=# CREATE USER issec_user WITH PASSWORD 'your_password';
postgres=# CREATE DATABASE issec_db OWNER issec_user;
postgres=# \q
```

### 4. Configurar variables de entorno

```bash
cp .env.example .env
# Editar .env con tus credenciales
```

**Variables requeridas:**

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `DATABASE_URL` | URL de conexión PostgreSQL | `postgresql://user:pass@localhost/issec_db` |
| `SECRET_KEY` | Clave secreta Flask | Cadena aleatoria de 32+ caracteres |

### 5. Inicializar base de datos

```bash
python scripts/create_tables.py
```

### 6. Ejecutar aplicación

```bash
flask run
```

La aplicación estará disponible en: http://localhost:5006

## Credenciales por Defecto

- **Email:** admin@issec.com
- **Password:** admin123

> ⚠️ **Importante:** Cambiar la contraseña del admin inmediatamente después del primer login.

## Problemas Comunes

### Error de conexión a PostgreSQL

Verificar que el servicio esté corriendo:
```bash
sudo systemctl status postgresql
```

### Error de permisos en scripts

```bash
chmod +x scripts/setup.sh
```

## Estructura del Proyecto

```
issec-toolset/
├── app/                 # Aplicación Flask
│   ├── models/          # Modelos SQLAlchemy
│   ├── routes/          # Endpoints/Rutas
│   ├── services/        # Lógica de negocio
│   ├── templates/       # Templates Jinja2
│   └── static/          # CSS, JS, imágenes
├── scripts/             # Scripts de utilidad
├── migrations/          # Migraciones Alembic
├── docs/                # Documentación
└── tests/               # Tests
```
