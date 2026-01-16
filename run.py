from app import create_app, db
from config import Config
from models import User

app = create_app(Config)

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

if __name__ == '__main__':
    app.run(debug=True)