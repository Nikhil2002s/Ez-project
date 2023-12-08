# app.py
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_bcrypt import Bcrypt

app = Flask(_name_)
api = Api(app)
bcrypt = Bcrypt(app)

# Database (SQLite for simplicity)
# In a production environment, consider using a more robust database.
users_db = {}
files_db = {}

class User:
    def _init_(self, username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

class File:
    def _init_(self, filename, filetype, owner):
        self.filename = filename
        self.filetype = filetype
        self.owner = owner

class OpsUser(Resource):
    def post(self):
        # Operation User Registration
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        users_db[username] = User(username, password)
        return {'message': 'Operation User registered successfully.'}

class ClientUser(Resource):
    def post(self):
        # Client User Registration
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        users_db[username] = User(username, password)
        return {'message': 'Client User registered successfully.'}

class Login(Resource):
    def post(self):
        # User Login
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = users_db.get(username)

        if user and bcrypt.check_password_hash(user.password, password):
            return {'message': 'Login successful.'}
        else:
            return {'message': 'Invalid credentials.'}, 401

class UploadFile(Resource):
    def post(self):
        # Upload File
        data = request.get_json()
        username = data.get('username')
        user = users_db.get(username)

        if user:
            file = data.get('file')
            filename = file.get('filename')
            filetype = file.get('filetype')

            if filetype in ['pptx', 'docx', 'xlsx'] and username == 'ops_user':
                files_db[filename] = File(filename, filetype, username)
                return {'message': 'File uploaded successfully.'}
            else:
                return {'message': 'Ops User is allowed to upload pptx, docx, and xlsx files.'}, 403
        else:
            return {'message': 'User not found.'}, 404

class DownloadFile(Resource):
    def get(self, assignment_id):
        # Download File
        user = users_db.get(request.headers.get('username'))

        if user and user.username == 'client_user':
            file = files_db.get(assignment_id)

            if file:
                # Generate secure download link (dummy link for illustration)
                download_link = f'/download-file/{assignment_id}'
                return {'download-link': download_link, 'message': 'success'}
            else:
                return {'message': 'File not found.'}, 404
        else:
            return {'message': 'Unauthorized access.'}, 403

api.add_resource(OpsUser, '/ops-user')
api.add_resource(ClientUser, '/client-user')
api.add_resource(Login, '/login')
api.add_resource(UploadFile, '/upload-file')
api.add_resource(DownloadFile, '/download-file/<string:assignment_id>')

if _name_ == '_main_':
    app.run(debug=True)
