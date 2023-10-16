import os
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api, Resource, fields
from flask_cors import CORS
from dotenv import load_dotenv
from flask_migrate import Migrate  

load_dotenv()

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user-authentication.db'

db = SQLAlchemy(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)  # Initialize Migrate with your Flask app and SQLAlchemy

api = Api(app, doc='/docs')

# User model (you already have it)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    userName = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

# Signup endpoint
@api.route('/signup', methods=['POST'])
class Signup(Resource):
    signup_model = api.model(
        'Signup',
        {
            'userName': fields.String(),
            'email': fields.String(),
            'password': fields.String(),
        }
    )

    @api.expect(signup_model)
    def post(self):
        data = request.get_json()
        username = data['userName']
        email = data['email']
        password = data['password']

        # Check if the user already exists
        existing_user = User.query.filter_by(userName=username).first()
        if existing_user:
            return {'message': 'User already exists'}, 409

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user
        new_user = User(userName=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User created successfully'}, 201

# Login endpoint
@api.route('/login', methods=['POST'])
class Login(Resource):
    login_model = api.model(
        'Login',
        {
            'userName': fields.String(),
            'password': fields.String(),
        }
    )

    @api.expect(login_model)
    def post(self):
        data = request.get_json()
        username = data['userName']
        password = data['password']

        user = User.query.filter_by(userName=username).first()

        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.userName)
            refresh_token = create_refresh_token(identity=user.userName)

            # Include the username in the response
            return {'access_token': access_token, 'refresh_token': refresh_token, 'username': user.userName}, 200
        else:
            return {'message': 'Invalid credentials'}, 401

if __name__ == '__main__':
    app.run()
