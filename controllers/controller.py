import datetime
import uuid
from functools import wraps
import jwt
from connections.connection import db
from flask import current_app as app
from flask import jsonify, make_response, request
from models.books import Book
from models.persons import Person
from werkzeug.security import check_password_hash, generate_password_hash

app.config['SECRET_KEY'] = 'thisissecret'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        token = None        
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            
        if not token:
            return jsonify({'msg': "Token is Missing..!!!!"})
        
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'])
            # current_user = Person.query.filter_by(public_id=data['public_id']).first()
            
        except:
            return jsonify({'msg' : "Token is Invalid"})        
        
        return f(*args, **kwargs)
    
    return decorated

        

# =======================================================================================
#                               SERVICES FOR PERSON TABLE
# =========================================================================================


@app.route('/get_all', methods=['GET'])
@token_required
def all_data():
    
    persons = Person.query.all()
    
    output = []
    
    for person in persons:
        data = {}
        
        data['admin'] = person.admin
        data['public_id'] = person.public_id
        data['name'] = person.name
        
        output.append(data)   
        
    return jsonify({"Data":output})


@app.route('/get_one/<public_id>', methods=['GET'])
@token_required
def one_data(public_id):    
        
    person = Person.query.filter_by(public_id=public_id).first()
    
    output = []
    data = {}
        
    data['admin'] = person.admin
    data['public_id'] = person.public_id
    data['name'] = person.name
        
    output.append(data)   
        
    return jsonify({"Data":output})


@app.route('/create', methods=['POST'])
def create_data():
    
    data = request.get_json()
    
    hashed_password = generate_password_hash(data['password'], method='sha256')
    
    new_user = Person(id=data['id'], public_id = str(uuid.uuid4()), name=data['name'], password = hashed_password, admin = False )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'msg' : 'Data Created Successfully...!!!'})

@app.route('/update/<public_id>', methods=['PUT'])
@token_required
def update_data(public_id):  
    
    data = request.get_json()
    person_data = Person.query.all()
    
    # if person_data:    
    
    #     person_data.admin = data['admin']
        
    for person in person_data:
        if person.public_id == data['public_id']:
            person.id = data['id']
            person.name = data['name']
            person.admin = data['admin']
            
            hashed_password = generate_password_hash(data['password'], method='sha256')
                
            person.password = hashed_password
        
    try:                
        db.session.commit()
    except Exception as e:
        print('Exception: {}'.format(e))
            
    return jsonify({'msg' : 'Data updated Successfully..!!!!'})
    
    # return jsonify({'msg' : 'You are not authorized person to perform this operation..!!!'})

@app.route('/delete/<public_id>', methods=['DELETE'])
@token_required
def get_all_data(public_id):
    
    person_data = Person.query.filter_by(public_id=public_id).first()
    
    db.session.delete(person_data)
    db.session.commit()
    
    return jsonify({'msg' : 'Data deleted Successfully..!!!'})

@app.route('/login')
def login():
    
    auth = request.authorization       
        
    if not auth or not auth.username or not auth.password:
        return make_response('Could Not Verify',401,{'WWW-Authenticate' : 'Basic realm = "Login required"'})    

    user = Person.query.filter_by(name=auth.username).first()
        
    if not user:
        return make_response('Could Not Verify',401,{'WWW-Authenticate' : 'Basic realm = "Login required"'})    
        
    if check_password_hash(user.password,auth.password):
            
                    
        payload = {
                "username" : auth.username,
                'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
                "public_id" : user.public_id    
                }
            
        secret = app.config['SECRET_KEY']
            
        token = jwt.encode(payload,secret)
            
        return jsonify({'token' : token})
        
    
    return make_response('Could Not Verify',401,{'WWW-Authenticate' : 'Basic realm = "Login required"'})




# =======================================================================================
#                                SERVICES FOR BOOKS TABLE
# =========================================================================================




@app.route('/get_all_b', methods=['GET'])
def get_all():
    
    books = Book.query.all()
    
    output = []
    
    for book in books:
        data = {}
        
        data['b_id'] = book.b_id
        data['b_name'] = book.b_name
        data['b_status'] = book.b_status
        
        output.append(data)   
        
    return jsonify({"Data":output})

@app.route('/get_one_b/<int:b_id>', methods=['GET'])
def get_one(b_id):
    book = Book.query.filter_by(b_id=b_id).first()
    
    output = []
    data = {}
        
    data['b_id'] = book.b_id
    data['b_name'] = book.b_name
    data['b_status'] = book.b_status
        
    output.append(data)   
        
    return jsonify({"Data":output})

@app.route('/add_book', methods=['POST'])
def create():
    
    data = request.get_json()
    
    p_data = db.session.query(Person).filter_by(name=data['name']).first()
    
    new_rec = Book(b_id=data['b_id'],b_name=data['b_name'],b_status = data['b_status'],owner=p_data)
    
    db.session.add(new_rec)
    db.session.commit()
    
    return jsonify({'msg' : 'Data Created Successfully...!!!'})


@app.route('/update_book/<int:b_id>', methods=['PUT'])
def update(b_id): 
    
    data = request.get_json()
    book_data = Book.query.all()    
        
    for book in book_data:
        if book.b_id == data['b_id']:
            book.b_name = data['b_name']
            book.b_status = data['b_status']           
        
    try:                
        db.session.commit()
    except Exception as e:
        print('Exception: {}'.format(e))
            
    return jsonify({'msg' : 'Data updated Successfully..!!!!'})