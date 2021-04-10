from flask import Flask,jsonify,request
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash,check_password_hash
from sqlalchemy.exc import IntegrityError
from functools import wraps
import jwt
import datetime


app= Flask(__name__)
cors=CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config["SECRET_KEY"]="uniquekeyformyapp"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///userdata.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    first_name=db.Column(db.String(100),nullable=False)
    last_name=db.Column(db.String(100),nullable=False)
    email=db.Column(db.String(80),unique=True,nullable=False)
    password=db.Column(db.String(80),nullable=False)

def token_required(f):
    @wraps(f)
    def check_token(*args,**kwargs):
        token=request.args.get('token')
        if not token:
            return jsonify({'status': "failure",'message': "Provide a Token"}),401
        try:
            status=jwt.decode(token,app.config['SECRET_KEY'],algorithms=["HS256"]),401
            print("STATUS-->",status)
        except:
            return jsonify({'status': "failure",'message': "Not Authenticated"}), 403

        return f(*args,**kwargs)
    return check_token


@app.route('/api/user',methods=['GET'])
@token_required
@cross_origin()
def index():
    return jsonify({'status': "success",'message': "Authenticated User"}),200


@app.route('/api/user/signup',methods=['POST'])
@cross_origin()
def user_signup():
    print("Sign up request")
    data=request.get_json(force=True) 
    hashed_password=generate_password_hash(data['password'],method='sha256')
    new_user=User(first_name=data['first_name'],last_name=data['last_name'],email=data['email'],password=hashed_password)
    db.session.add(new_user)
    try:
        db.session.commit()
        token= jwt.encode({"email": data['email'], "exp": datetime.datetime.utcnow() +datetime.timedelta(minutes=5)},app.config["SECRET_KEY"])
        return jsonify({'status': "success",'message': "User created",'token':token}),201
    except IntegrityError:
        return jsonify({'status': "failure",'message': "User already exists (Email taken)"}),409
@app.route('/api/user/signin',methods=['POST'])
@cross_origin()
def user_signin():
    print("Sign in request")
    data=request.get_json(force=True) 
    user=User.query.filter_by(email=data["email"]).first()
    print(user)
    if user:
        check_password=check_password_hash(user.password,data['password'])
        if check_password:
            token= jwt.encode({"email": user.email, "exp": datetime.datetime.utcnow() +datetime.timedelta(minutes=5)},app.config["SECRET_KEY"])
            return jsonify({'status': 'success','message': 'User Logged in','token':token}),200
    return jsonify({'status': "failure",'message': 'Invalid Credentials'}) ,401

if __name__ == '__main__':
    app.run(debug=False)