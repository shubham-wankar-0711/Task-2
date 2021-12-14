from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def auto_migrate():
    import models.persons
    import models.books
    
    db.create_all()
    db.session.commit()
