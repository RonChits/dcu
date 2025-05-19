from app import app, db
from models import User

with app.app_context():
    # List all users
    users = User.query.all()
    print(f"Total users: {len(users)}")

    # Print user details
    for user in users:
        print(f"""
        ID: {user.id}
        Username: {user.username}
        Email: {user.email}
        Name: {user.first_name} {user.last_name}
        Password Hash: {user.password}
        """)