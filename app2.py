from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] ='thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incident.db' # the pass where the database is intalled

db =SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    firstname = db.Column(db.String(80))
    lastname = db.Column(db.String(80))
    othernames = db.Column(db.String(80))
    phonenumber = db.Column(db.String(80))
    name = db.Column(db.String(80))
    email = db.Column(db.String(80))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    registered = db.Column(db.DateTime)



class Todo(db.Model):   #class Incident
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)
    createdOn = db.Column(db.DateTime)
    createdBy = db.Column(db.String(80))
    reportType = db.Column(db.String(80))
    location = db.Column(db.String(80))
    status  = db.Column(db.String(80))
    # images  = db.Column(db.image)
    # videos  = db.Column(db.image)
    comment = db.Column(db.String(100))

   #a decprator to check if the token is valid
def required_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' is request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message': 'Token is invalid'}), 403
        return f( current_user, *args, **kwargs)
        return decorated


@app.route('/users', methods=['GET'])
#@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function because your not admin!'})
    users = User.query.all()
    output = []
    for user in users:
       #my user dictionary
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})

@app.route('/users/<public_id>', methods=['GET'])
#@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function because your not admin!'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})
   #my user dictionary
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})

@app.route('/users', methods=['POST'])
# @token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function because your not admin!'})
    data = request.get_json()
    hash_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=harshed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})

@app.route('/users/<public_id>', methods=['PUT'])
# @token_required
def promote_user(current_user, public_id):    #this promotes user ids from user to admin
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function because your not admin!'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'Ther user has been promoted'})

@app.route('/users/<public_id>', methods=['DELETE'])
# @token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function because your not admin!'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate:' 'Basic realm="Login required"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate:' 'Basic realm="Login required"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate:' 'Basic realm="Login required"'})

    #creating incident routes for all normal api users to report incidents

@app.route('/incident', methods=['POST'])
# @token_required
def create_incident(current_user):
    data = request.get_json()

    #create an incident object
    new_incident = To(text=data["text"], complete=False, user_id=current_user.id)
    db.session.add(new_incident)
    db.session.commit()

    return jsonify({'message' : "Incident created!"})

@app.route('/incident', methods=['GET'])
# @token_required
def get_all_incident(current_user):
    incidents = Incident.query.filter_by(user_id=current_user.id).all()

    output = []

    for incident in incidents:
        incident_data = {}
        incident_data['id'] = incident.id
        incident_data['text'] = incident.text
        incident_data['complete'] = incident.complete
        output.append(incident_data)

    return jsonify({'incidents' :output})

@app.route('/incident/<incident_id>', methods=['GET'])
# @token_required
def get_one_incident(current_user, incident_id):
    incident = Incident.query.filter_by(id=incident_id, user_id=current_user.id).first()

    if not incident:
        return jsonify({'message' : 'No incident found!'})

    incident_data = {}
    incident_data['id'] = incident.id
    incident_data['text'] = incident.text
    incident_data['complete'] = incident.complete
    return jsonify(incident_data)

@app.route('/incident/<incident_id>', methods=['PUT'])
# @token_required
def complete_incident(current_id, incident_id):
    incident = Incident.query.filter_by(id=incident_id, user_id=current_user.id).first()

    if not incident:
        return jsonify({'message' : 'No Incident found!'})
    incident.complete = True
    db.session.commit()

    return jsonify({'message' : 'Incident item has been completed!'})

@app.route('/incident/<incident_id>', methods=['DELETE'])
# @token_required
def delete_incident(current_id, incident_id):
    incident = Incident.query.filter_by(id=incident_id, user_id=current_user.id).first()

    if not incident:
        return jsonify({'message' : 'No incident found!'})

    db.session.delete(incident)
    db.session.commit()

    return jsonify({'message' : 'Incident item deleted!'})

if __name__ =='__main__':
    app.run(debug=True)