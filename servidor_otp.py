from flask import Flask, request, make_response
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hmac
import hashlib
import base64
import yagmail

app = Flask(_name_)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:aelnuq2012@localhost/otp_server'

db = SQLAlchemy(app)

cipher_rsa = ""
decipher_rsa = ""
otp_value = ""
contador_OTP = ""

EMAIL_SENDER = "send.hotpt@gmail.com"
EMAIL_API_KEY = "pnnlmjvbuymresaw"

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.LargeBinary, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)

    def _repr_(self):
        return f"User: {self.username}"

    def _init_(self, username, password):
        self.username = username
        self.password = password

class Keys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_key = db.Column(db.LargeBinary, nullable=False)
    private_key = db.Column(db.LargeBinary, nullable=False)

    def _repr_(self):
        return f"Public_key: {self.public_key}"

    def _init_(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

class OtpInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    initial_count = db.Column(db.Integer, nullable=False)
    current_count = db.Column(db.Integer, nullable=False)
    increment_count_by = db.Column(db.Integer, nullable=False)

    def _repr_(self):
        return f"OtpInfo: {self.id, self.user_id, self.initial_count, self.current_count, self.increment_count_by}"
    
    def _init_(self, user_id, initial_count, current_count, increment_count_by):
        self.user_id = user_id
        self.initial_count = initial_count
        self.current_count = current_count
        self.increment_count_by = increment_count_by

def format_user(user):
    return {
        "id": user.id,
        "username": user.username,
        "password": user.password
    }

def format_public_key(public_key):
    return {
        "public_key": public_key
    }

with app.app_context():
    db.create_all()
    keys_pair = Keys.query.get(1)
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(keys_pair.public_key))
    decipher_rsa = PKCS1_OAEP.new(RSA.import_key(keys_pair.private_key))

@app.route('/create_user', methods=['POST'])
def create_user():
    username = request.json['username']
    password = request.json['password']
    encrypted_username = cipher_rsa.encrypt(username.encode())
    encrypted_password = cipher_rsa.encrypt(password.encode())
    user = Users(username=encrypted_username, password=encrypted_password)
    db.session.add(user)
    db.session.commit()
    response = make_response('Usuario creado exitosamente!')
    response.status_code = 201
    return response

@app.route('/auth_user', methods=['POST'])
def auth_user():
    username = request.json['username']
    password = request.json['password']
    users = Users.query.all()

    user_exists = False
      
    for user in users:
        db_username = decipher_rsa.decrypt(user.username).decode()
        db_password = decipher_rsa.decrypt(user.password).decode()
        print(db_username)
        print(db_password)
        if username == db_username and password == db_password:
            user_exists = True

    if user_exists:
        response = make_response('Access granted!')
        response.status_code = 200
        return response
    else:
        response = make_response('Access denied!')
        response.status_code = 404
        return response
    
@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    keys_pair = Keys.query.get(1)
    return format_public_key(keys_pair.public_key.decode())

@app.route('/generate_otp', methods=['POST'])
@cross_origin()
def generador_hotp():
    username = request.json['username']
    email_to_send = request.json['email_to_send']
    otpInfo = OtpInfo.query.filter_by(user_id = 1).first()
    current_count = 0
    increment_count_by = 0

    if otpInfo is None:
        initial_count = 1
        current_count = 1
        increment_count_by =1
        otp_info = OtpInfo(user_id=1, initial_count=initial_count, current_count=current_count, increment_count_by=increment_count_by)
        db.session.add(otp_info)
        db.session.commit()
    else:
        current_count = otpInfo.current_count
        increment_count_by = otpInfo.increment_count_by

    if len(username)%4 != 0:
        print("entre")
        username = username[0:(int(len(username)/4))*4]
    
    otp_value = generador_hotp(username, current_count)

    yag = yagmail.SMTP(user=EMAIL_SENDER, password=EMAIL_API_KEY)
    yag.send(email_to_send, "Autenticación de dos factores","El código OTP es: "+otp_value)

    otpInfo.current_count = otpInfo.current_count + otpInfo.increment_count_by
    db.session.commit()

    response = make_response({'otp_value': otp_value})
    response.status_code = 201

    return response
    
@app.route('/verify_otp/<user_id>/<username>', methods=['GET'])
def verify_otp(user_id, username):

    otpInfo = OtpInfo.query.filter_by(user_id = user_id).first()

    if (len(username)%4) != 0:
        username = username[0:(len(username)%4)*4]

    otp_value = request.json['otp_value']
    expected_otp = generador_hotp(username, otpInfo.current_count)

    if otp_value == expected_otp:
        response = make_response('Access granted!')
        response.status_code = 201
        return response
       
    response = make_response('Access denied!')
    response.status_code = 404
    return response

@app.route('/get_user/<id>', methods=['GET'])
def get_user(id):
    user = Users.query.get(id)
    username = decipher_rsa.decrypt(user.username).decode()
    password = decipher_rsa.decrypt(user.password).decode()
    print(username)
    print(password)
    response = make_response('prueba')
    response.status_code = 200
    return response

@app.route('/generate_key_pairs', methods=['GET'])
def generate_key_pairs():
    key = RSA.generate(2048)
    public_key = key.public_key().export_key(format="PEM")
    private_key = key.export_key(format="PEM")
    key_pairs = Keys(public_key=public_key, private_key=private_key)
    db.session.add(key_pairs)
    db.session.commit()
    response = make_response('Llaves generadas exitosamente!')
    response.status_code = 200
    return response

def generador_hotp(key, counter):
    key = base64.b64decode(key)
    counter = int(counter).to_bytes(8, byteorder='big')

    hmac_value = hmac.new(key, counter, hashlib.sha1).digest()

    offset = hmac_value[-1] & 0xf

    code = ((hmac_value[offset] & 0x7f) << 24 |
            (hmac_value[offset + 1] & 0xff) << 16 |
            (hmac_value[offset + 2] & 0xff) << 8 |
            (hmac_value[offset + 3] & 0xff)) % 1000000

    return f'{code:06d}'

if _name_ == '_main_':
    app.run()
