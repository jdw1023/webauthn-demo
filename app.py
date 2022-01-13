from sqlalchemy.ext.mutable import MutableList
import flask
import json
import webauthn
from webauthn.helpers.options_to_json import options_to_json
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from webauthn.helpers.structs import *

RP_NAME = "WebAuthn Demo"
RP_ID = "localhost"
ORIGIN = "http://localhost:5000"

app = flask.Flask(__name__)
app.secret_key = 'super secret key'  # TODO: use environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///webauthn.db'

db = SQLAlchemy(app)

# https://docs.sqlalchemy.org/en/14/orm/extensions/mutable.html#sqlalchemy.ext.mutable.MutableList

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    # len("pbkdf2:sha256:260000") + len("$") + len(salt) + len("$") + len(hash) == 102
    password = db.Column(db.String(102), nullable=False)
    # The challenge is store temporarily in the database https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
    auth_challenge = db.Column(db.String(64)) # https://github.com/duo-labs/py_webauthn/blob/master/webauthn/helpers/generate_challenge.py#L4
    reg_challenge = db.Column(db.String(64)) # default is 64 bytes
    # mutable is needed to allow for the credentials to be updated
    credentials = db.Column(MutableList.as_mutable(db.PickleType))

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return '<User %r>' % self.username

db.create_all()
db.session.commit()

@app.route('/')
def index():
    return flask.render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET':
        return flask.render_template('login.html', error='', webauthn=(flask.request.args.get('webauthn') == 'true'))
    username = flask.request.form['username']
    password = flask.request.form['password']
    user = User.query.filter_by(username=username).first()
    # successful login with username and password
    if user and user.check_password(password):
        flask.session['username'] = username
        return flask.redirect(flask.url_for('index'))
    elif user:
        return flask.render_template('login.html', error="Wrong password")
    else:
        return flask.render_template('login.html', error="User not found")

@app.route('/logout')
def logout():
    flask.session.pop('username', None)
    return flask.redirect(flask.url_for('index'))

@app.route('/login/webauthn', methods=['get'])
def generate_webauthn_auth():
    print("start generate auth")
    username = flask.request.args.get('username')
    user = User.query.filter_by(username=username).first()
    if not user:
        return flask.jsonify({'error': 'User not found'})
    allow_credentials = [PublicKeyCredentialDescriptor(id=cred["id"]) for cred in user.credentials]
    simple_auth_options = webauthn.generate_authentication_options(rp_id=RP_ID, allow_credentials=allow_credentials)
    user.auth_challenge = simple_auth_options.challenge
    db.session.commit()
    return options_to_json(simple_auth_options)

@app.route('/login/webauthn/verify', methods=['POST'])
def login_webauthn_verify():
    print("start verify auth")
    username = flask.request.args.get('username')
    credential = flask.request.get_data()
    # print(credential)
    user = User.query.filter_by(username=username).first()
    if username is None:
        return flask.jsonify({"error": "No username provided"})
    if credential is None:
        return flask.jsonify({"error": "No credential provided"})
    if user is None:
        return flask.jsonify({"error": "No user found"})
    if user.credentials is None:
        return flask.jsonify({"error": "No credentials found"})
    try:
        # print(credential)
        credential = AuthenticationCredential.parse_raw(credential)
        # print(credential)
        authentication_verification = webauthn.verify_authentication_response(credential=credential, expected_challenge=user.auth_challenge, expected_rp_id=RP_ID,
                                                                              expected_origin=ORIGIN, credential_public_key=user.credentials[0]["public_key"], credential_current_sign_count=user.credentials[0]["sign_count"])
        # print(authentication_verification)
        # print("aaa")
        flask.session['username'] = username
        return flask.jsonify({"verified": True, "data": json.loads(options_to_json(authentication_verification))})
    except Exception as e:
        print(e)
        return flask.jsonify({"error": str(e)})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if flask.request.method == 'GET':
        return flask.render_template('register.html', error='')
    username = flask.request.form['username']
    password = flask.request.form['password']
    user = User.query.filter_by(username=username).first()
    if username is None:
        return flask.render_template('register.html', error='No username provided')
    if password is None:
        return flask.render_template('register.html', error='No password provided')
    if user is not None:
        return flask.render_template('register.html', error='User already exists')
    user = User(username=username, password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    flask.session['username'] = username
    return flask.redirect(flask.url_for('index'))

# TODO: a way to delete credentials
@app.route('/register/webauthn', methods=['GET'])
def register_webauthn():
    username = flask.session['username']
    user = db.session.query(User).filter_by(username=username).first()
    if username is None:
        return flask.redirect(flask.url_for('login'))
    if user is None:
        return flask.redirect(flask.url_for('register'))
    options = webauthn.generate_registration_options(
        rp_name=RP_NAME,
        rp_id=RP_ID,
        user_id=str(user.id),
        user_name=user.username,
        exclude_credentials=[
            {"type": "public-key", "id": cred['id'], "transports": cred['transports']} for cred in user.credentials or []
        ]
    )
    user.reg_challenge = options.challenge
    db.session.commit()
    return flask.render_template('register_webauthn.html', user=user, options=json.loads(webauthn.options_to_json(options)))


@app.route('/register/webauthn/verify', methods=['POST'])
def register_webauthn_verify():
    cred = flask.request.get_data()
    username = flask.session['username']
    if username is None:
        return flask.jsonify({'verified': False, 'msg': 'Not logged in', 'status': 400})
    if cred is None:
        return flask.jsonify({'verified': False, 'msg': 'No credential provided', 'status': 400})
    user = db.session.query(User).filter_by(username=username).first()
    try:
        credential = RegistrationCredential.parse_raw(cred)
        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=user.reg_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )
    except Exception as err:
        return {"verified": False, "msg": str(err), "status": 400}

    new_credential = {
        "id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
    }

    credential_dict = json.loads(cred)
    if "transports" in credential_dict:
        new_credential['transports'] = credential_dict["transports"]

    if user.credentials is None:
        user.credentials = [new_credential]
    else:
        user.credentials.append(new_credential)

    user.reg_challenge = None
    db.session.commit()
    return {"verified": True}

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
