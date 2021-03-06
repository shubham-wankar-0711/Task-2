from flask import Flask
import os
from connections.connection import db,auto_migrate

app = Flask(__name__)
app.config.from_pyfile(os.path.join(os.getcwd(), 'configs', 'config.py'))
db.init_app(app)

with app.app_context():
    auto_migrate()
    
    from controllers import controller
    
    

if __name__ == '__main__':
    app.run()
    