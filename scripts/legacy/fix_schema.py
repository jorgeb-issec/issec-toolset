from app import create_app
from app.extensions import db
from sqlalchemy import text

app = create_app()

with app.app_context():
    try:
        print("Intentando agregar columna 'products' a la tabla 'companies'...")
        # Check if column exists first to avoid error? Or just try/catch
        # Postgres doesn't support "IF NOT EXISTS" for ADD COLUMN in older versions, but 9.6+ does. 
        # Safest is just catch exception or check. 
        # Let's try direct ALTER.
        with db.engine.connect() as conn:
            conn.execute(text("ALTER TABLE companies ADD COLUMN products JSONB DEFAULT '[]'"))
            conn.commit()
        print("Columna 'products' agregada correctamente.")
    except Exception as e:
        print(f"Nota: {e}")
        print("Es posible que la columna ya exista o hubo otro error. Verifica la base de datos.")
