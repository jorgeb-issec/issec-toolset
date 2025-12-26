import uuid
from werkzeug.security import generate_password_hash, check_password_hash

def gen_uuid():
    return str(uuid.uuid4())

def hash_password(password):
    return generate_password_hash(password)

def verify_password(hash_, password):
    return check_password_hash(hash_, password)
