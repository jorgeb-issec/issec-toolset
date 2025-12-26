# reset_db.py
from app import create_app
from app.extensions.db import db

app = create_app()

def reset_database():
    print("⚠️  ATENCIÓN: Esto borrará TODA la base de datos.")
    confirm = input("¿Estás seguro? Escribe 'si' para continuar: ")
    
    if confirm.lower() == 'si':
        with app.app_context():
            print("Eliminando tablas...")
            db.drop_all()
            print("Creando tablas limpias...")
            db.create_all()
            print("✅ Base de datos reseteada correctamente.")
    else:
        print("Operación cancelada.")

if __name__ == "__main__":
    reset_database()