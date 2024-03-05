from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo.errors import PyMongoError

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/users'
app.config['JWT_SECRET_KEY'] = 'Priyanshu'  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # Token expires in 1 hour
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

try:
    mongo.db.command('ping')
    print("Connected to MongoDB successfully")
except PyMongoError as e:
    print("Failed to connect to MongoDB:", e)

# Error Handling
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
def error_handler(error):
    return jsonify({'message': str(error)}), error.code

# Signup
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    
    if not email or not username or not password:
        return jsonify({'message': 'Email, username, and password are required'}), 400
    
    existing_user = mongo.db.users.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    mongo.db.users.insert_one({'username': username, 'email': email, 'password': hashed_password})
    access_token = create_access_token(identity=email)
    return jsonify({'message': 'Signup successful', 'token': access_token}), 201

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Incorrect email or password'}), 401

    access_token = create_access_token(identity=email)
    return jsonify({'message': 'Login successful', 'access_token': access_token}), 200

# CRUD Operations

# Add Product
@app.route('/product/add', methods=['POST'])
@jwt_required()
def add_product():
    data = request.json
    required_fields = ['name', 'desc', 'price', 'email']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    email = data['email']
    if not mongo.db.users.find_one({'email': email}):
        return jsonify({'message': 'User does not exist'}), 404

    product = {
        'product_name': data['name'],
        'product_desc': data['desc'],
        'product_price': data['price'],
        'product_email': email
    }

    mongo.db.product.insert_one(product)
    return jsonify({'message': 'Product added successfully'}), 201

# Show Product
@app.route('/product', methods=['GET'])
@jwt_required()
def show_product():
    email = get_jwt_identity()
    products = mongo.db.product.find({'product_email': email})
    return jsonify({'products': list(products)}), 200

# Edit Product
@app.route('/product/edit/<product_id>', methods=['PUT'])
@jwt_required()
def edit_product(product_id):
    email = get_jwt_identity()
    product = mongo.db.product.find_one({'_id': product_id, 'product_email': email})
    if not product:
        return jsonify({'message': 'Product not found'}), 404

    data = request.json
    updated_product = {
        'product_name': data.get('name', product['product_name']),
        'product_desc': data.get('desc', product['product_desc']),
        'product_price': data.get('price', product['product_price'])
    }

    mongo.db.product.update_one({'_id': product_id}, {'$set': updated_product})
    return jsonify({'message': 'Product updated successfully'}), 200

# Delete Product
@app.route('/product/delete/<product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    email = get_jwt_identity()
    result = mongo.db.product.delete_one({'_id': product_id, 'product_email': email})
    if result.deleted_count == 0:
        return jsonify({'message': 'Product not found'}), 404

    return jsonify({'message': 'Product deleted successfully'}), 200

# Get Users
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = mongo.db.users.find({}, {'_id': 0, 'username': 1, 'email': 1})
    return jsonify({'users': list(users)}), 200

# Add User
@app.route('/users', methods=['POST'])
@jwt_required()
def add_user():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({'message': 'Username and email are required'}), 400

    if mongo.db.users.find_one({'email': email}):
        return jsonify({'message': 'User already exists'}), 400

    user = {'username': username, 'email': email}
    mongo.db.users.insert_one(user)
    return jsonify({'message': 'User added successfully'}), 201

if __name__ == '__main__':
    app.run(debug=True, port=3001)