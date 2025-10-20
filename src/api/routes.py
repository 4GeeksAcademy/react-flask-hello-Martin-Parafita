"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
import bcrypt
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import jwt_manager


api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/register', methods=['POST'])
def register():

    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Ese usuario ya existe"}), 400

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    user = User(email=email, password=hashed_password.decode('utf-8'), is_active=True)
    db.session.add(user)
    db.session.commit()

    return jsonify(user.serialize()), 201

@api.route('/login', methods=['POST'])
def login():

    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user:
        jsonify({"msg": "User don't exist"}), 400

    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({"msg": "Wrong password"}), 401
    
    token = create_access_token(identity=user.id)
    return jsonify({ "token": token, "user": user.serialize() }), 200

    