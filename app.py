from flask import Flask, jsonify, request
from datetime import datetime, timedelta, timezone
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity,unset_jwt_cookies,jwt_required,JWTManager
from models import db,User
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import json

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.config['SECRET_KEY'] = 'jiraiya1729'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskdb.db'

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)

SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = True
db.init_app(app)
bcrypt = Bcrypt(app)

with app.app_context():
    db.create_all()

@app.route("/")
def hello_world():
    return "<h1> hello worldw</h1>"

@app.route("/logintoken", methods=["POST"])
def create_token():
    email = request.json.get("email",None)
    password = request.json.get("password",None)
    user = User.query.filter_by(email=email).first()
    
    # return "hello"
    # if email
    # if email != "test" or password != "test":
    #     return {"msge": "wrong email or password"}, 401
    
    if user is None:
        return jsonify({"error": "Wrong email or passwords"}), 401

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Unauthorized"}), 401
        
        
    access_token = create_access_token(identity=email)
    # response = {"access_token":access_token}
    
    return jsonify({
        "email": email,
        "access_token": access_token
    })
    
@app.route("/signup", methods=["POST"])
def signup():
    email = request.json["email"]
    password = request.json["password"]
    
    user_exists = User.query.filter_by(email=email).first() is not None
    
    if user_exists:
        return jsonify({"error": "Email already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password)
    name="jiraiya_" + str(datetime.utcnow().timestamp())
    new_user = User( name=name, email=email, password=hashed_password, about="sample")
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({
        "id": new_user.id,
        "email": new_user.email
    })
    
@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identify = get_jwt_identity())
            data = response.get_json()
            if type(data) is dict:
                data["access_token"] = access_token
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):
        return response
    
@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response 
    
@app.route('/profile/<getemail>')
@jwt_required()
def my_profile(getemail):
    print(getemail)
    if not getemail:
        return jsonify({
            "error": "Unauthorized Access"
        }), 401
    user = User.query.filter_by(email=getemail).first()
    
    response_body = {
        "id": user.id,
        "name":user.name,
        "email":user.email,
        "about":user.about
        
    }
    return response_body    


    
    
if __name__ == "__main__":
    app.run(debug=True)