from app import create_app
from app.models.user import User

app = create_app()

def check_users():
    with app.app_context():
        users = User.query.all()
        print(f"Total Users: {len(users)}")
        for u in users:
            print(f" - {u.username} (Email: {u.email}, ID: {u.id})")
            for role in u.company_roles:
                print(f"   * Company: {role.company.name if role.company else 'Global'} - Role: {role.role.name}")

if __name__ == "__main__":
    check_users()
