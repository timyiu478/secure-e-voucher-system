from flask import Flask, flash, request, render_template, redirect, url_for, session, logging, send_from_directory
from flask_wtf.csrf import CSRFProtect
from flask_sslify import SSLify
from secure import SecureHeaders
from jsbn import RSAKey
from flask_hashing import Hashing
import random
import string
from flask_security import Security, current_user, auth_required, UserMixin, RoleMixin, login_required, \
    SQLAlchemySessionUserDatastore, auth_token_required, http_auth_required, login_user, logout_user
from sqlalchemy import create_engine, Boolean, DateTime, Column, Integer, String, ForeignKey, TIMESTAMP, LargeBinary
from sqlalchemy.orm import scoped_session, sessionmaker, relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from flask_login import LoginManager
from flask_mail import Mail, Message
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from datetime import datetime,timedelta
import jwt
import time
from flask_qrcode import QRcode
import json
from Crypto.Cipher import AES
import base64
from des import DesKey
from Crypto.Hash import SHA256

app = Flask(__name__, static_url_path='')
app.config['SECRET_KEY'] = "4b59ab11db89739d98b88f0a7ba836f7"
app.config['SECURITY_TRACKABLE'] = False
app.config['SECURITY_REGISTERABLE'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['HASHING_METHOD'] = 'sha512'
app.config[
    'SQLALCHEMY_DATABASE_URI'] = "postgresql://nnkubnguoavtgv:1e997411bc8c6bc8538080ce6c18687284345a8f6d158371066c757034e8edb1@ec2-18-206-20-102.compute-1.amazonaws.com:5432/d804rvscjp3lja"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'comp3334grp2@gmail.com'
app.config['MAIL_PASSWORD'] = 'Comp3334grp@2    '
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
csrf = CSRFProtect(app)  # CSRFProctect
sslify = SSLify(app)  # redirect to HTTPS
hashing = Hashing(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"
login_manager.login_view = 'login'
secure_headers = SecureHeaders(content=False)  # https://secure.readthedocs.io/en/latest/headers.html#usage

rsa = RSAKey()
n="0xbf1c21d505bb0785eaa5671d6081d011e9cacfe08b18dd344e55557629d3aaf1015d26b7f47f1ba1e6e5244e019714434f6cd2157aef2544c52589c226fcbaace1fe08a50ca9d47a168f52fcde8b4a3e3952a3139b52126b254a0d0513bdfbed2474f07f7217b3ec4d6f04e4dcd771ea9ac28f38087bf03eaab51baa5469a92f06b8dba41d7b324a0ee6f62f117520b5ab6fd37d6fefc0f85d4ee4eb6252db95fe0e37161551613a852a5b82775ee560f1df88ac4fbec21955fabea7f622bb89c6e8cfc2bb8f1640ecaf5192739545d069816ffb54a9f06261ecc62e679432eb28af6340bc7f8a96c4b547f62013597bcc2deb8c770bd5e38e7aff125dd33403"
e="0x10001"
d="0x4cbd3328a2e07328e70bfbd7e404bc543518e758370288f093f3d81956ba540dea8a491ddce39d68e99a6175a155d5212227844473d4cb964dc3c1096136628f41400ca099f1280cce3a470c9b203b73b8f8e1dae1a79715c727710af4de78e6c498e0698c9acff8b72f393bdd21f5f04aac8d6de69a3de1d063383207650b525b772488e2bcdbd27f8dc0fae33a46946577b474bf87cf44b905f5847ea8e7a37b15b2c2baf2c89194bcc7c3eda86747a32e2f222dd16b583174b175e990f1186fb6fe8a0cebbec79089db0744e68f4098a30b2b50e5ec6ee66c41d144a31ced8a0a61f90e74b5f9a172a8262ad77f1039dfd1486a4d96612632988c7ddfc621"
p="0xe4535b322ca76d1c2081868a7abc4f480f57468d22b94a6a9ddad2c7b49a578450837f3363ea2887d5bfbe1b560c441d5cd51d875c6259d80cde75e569eb1f77b401cbd341b8333697ea192ae70bce84cb518e8e5f7fe5bbc9c4d663e5d1da7aa7ee625696b1f3517a4521e10e8d19496464a2a3abb72b6f39f984fa659d820f50ef1feebe5678c7"
q="0xd64605633e69df19a27effbb919372e757ac661f754f3a94b9fafd327db065e00db1c4eb72f66d42d45f05c6e374fda15049c757573bd9fcb6c36dc77699f7f8feae9fde23e71b9aad0254e3b3015ba07d887c39cf84a68de6ae9f81af22d8336d80d782991d8d6ca28c13afb90b04a7f40b6fb477b786e5"
dmp1="0xe0ddb75312e7516e02158e8b939521ffb61c1e3fa1931ad725dffcf6f1c78fa9a021e1849b4261e8657b119f9a7f3a1630f732bdbd1e9f9d480f4fcd41236f3a54edefef7f2a0a461a1753f20cda73ea14d39db25a1b7c061610e5943d231028fc7aaa1edd0b24b779d3dc29ea4acc3c9bc300ea7093551395e54831d321ec9569001852e8e200d"
dmq1="0x690aea993c7faa5f66c9db949849308b38efcb20a0e1b65632d65849e854119d451960f00bebc2a4807814dceba4eeb1a62a850ecc350b28587075e0d2c3a84ce88db2d1b3c818403b90690d3733f3373a532e9328a85efe31986999a9c1eb3b4af35eb3275cd577ec37bf6ee5c801005523461fb290c61"
coeff="0xcacf36be60fafe5f26c87b57ccc66dd55708d6aeb487c7b8b0de94ac3d85653b3cf0783dece6a5bbee0983fad998117385d6d652cc75aa45d3458682611f06de242a455c0cb31fd6b71392e7aaa2711c54c6a8481f35941e78b6c79473dd9e363c26819c790d073ff7bc9f99bf83e303bbb4b4bf2eb4348c408f91e85ac72cf496e9a2d2b5a4af47"
rsa.setPublic(n,e)
rsa.setPrivate(n,e,d)
rsa.setPrivateEx(n,e,d,p,q,dmp1,dmq1,coeff)

serializer = URLSafeTimedSerializer('secret-key')

# connect database
engine = create_engine(
    'postgresql://nnkubnguoavtgv:1e997411bc8c6bc8538080ce6c18687284345a8f6d158371066c757034e8edb1@ec2-18-206-20-102.compute-1.amazonaws.com:5432/d804rvscjp3lja')
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

# qrcode
QRcode(app)


# create db
def init_db():
    Base.metadata.create_all(bind=engine)



class Transaction(Base):
    __tablename__ = 'transaction'
    id = Column(Integer(), primary_key=True)
    from_user_id = Column('from_user_id', Integer(), ForeignKey('user.id'))
    to_user_id = Column('to_user_id', Integer(), ForeignKey('user.id'))
    timestamp = Column(TIMESTAMP(), nullable=False, server_default='now()')
    from_name = Column(String(255))
    to_name = Column(String(255))
    coupon_id = Column('coupon_id',Integer(),ForeignKey('coupon.id'))

    def __init__(self, from_user_id, to_user_id,from_name, to_name,coupon_id):
        self.from_user_id = from_user_id
        self.to_user_id = to_user_id
        self.from_name = from_name
        self.to_name = to_name
        self.coupon_id = coupon_id



# create models
class RolesUsers(Base):
    __tablename__ = 'roles_users'
    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id', Integer(), ForeignKey('user.id'))
    role_id = Column('role_id', Integer(), ForeignKey('role.id'))


class Role(Base, RoleMixin):
    __tablename__ = 'role'
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True)
    description = Column(String(255))


class User(Base, UserMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    username = Column(String(255))
    password = Column(String(255))
    salt = Column(String(255))
    hkidentity_confirmed = Column(Boolean)
    hkidentity_attempts_left = Column(Integer)
    last_login_at = Column(DateTime())
    current_login_at = Column(DateTime())
    last_login_ip = Column(String(100))
    current_login_ip = Column(String(100))
    login_count = Column(Integer)
    active = Column(Boolean())
    confirmed_at = Column(DateTime())
    roles = relationship('Role', secondary='roles_users',
                         backref=backref('users', lazy='dynamic'))
    pin_code = Column(String(255))
    pin_salt = Column(String(255))
    role_id = Column(Integer)

class HKID(Base):
    __tablename__ = "hkid"
    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id',Integer(), ForeignKey('user.id'))
    firstname = Column(LargeBinary(255))
    lastname = Column(LargeBinary(255))
    sex = Column(LargeBinary(255))
    birthday = Column(LargeBinary(255))
    hkid = Column(LargeBinary(255))

    def __init__(self, firstname,lastname, sex, birthday,hkid):
        self.firstname = firstname
        self.lastname = lastname
        self.sex = sex
        self.birthday = birthday
        self.hkid = hkid

#Base.metadata.tables["hkid"].create(bind = engine)



hkid_3des_key = DesKey(b"a key for TRIPLE") 
sha256 = SHA256.new()

# set flask-security
user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
security = Security(app, user_datastore)

#create hkid database
person1 = ['fe26ba074c73d4cbe1bdad50cc2379587a568e58853af2add08951bdd00103de','e634a178ebf6596533b557fa06b0f75b235e08f9f384339a0868855e9ecdb1fe','0d248e82c62c9386878327d491c762a002152d42ab2c391a31c44d9f62675ddf','680281cb6f6b3c15f44fc561a44fe8e4c8bd566a397a503f348d37ef64d409c6','358100c210df061db1f9a7a8945fa3140e169ddf67f7005c57c007647753e100']
person2 = ['da17c13402bca42e4f4dbd3fe1cb45919d80b42e0a4f1a3ebbab455e04285b60','f57ef13b35b15ea0eadafb0524bfa10792b7e79f05cb009854fe978fcf715d58','9f165139a8c2894a47aea23b77d330eca847264224a44d5a17b19db8b9a72c08','4567b9fd1993807f0c59e5af3031cfce32713d5f1e45dd6942f1c26fe35b542b','45b26c77079c3dbc7343aa4eeace51f033dea506c7881d9a39bf0b5932c93c16']
def create_hkid(person):
    encrypted_datas = []
    for i in range(5):
        encrypted_data = hkid_3des_key.encrypt(bytes(person[i], encoding='utf-8'))
        encrypted_datas.append(encrypted_data)
    db_session.add(HKID(lastname=encrypted_datas[0],firstname=encrypted_datas[1],sex=encrypted_datas[2],birthday=encrypted_datas[3],hkid=encrypted_datas[4]))
    db_session.commit()

def create_person_hkid():
    try:
        create_hkid(person1)
        create_hkid(person2)
    except Exception as error:
        return f"{error}"
    return "success!"

#print(create_person_hkid())

class Coupon(Base):
    __tablename__ = "coupon"
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True)
    amount = Column(Integer())
    quantity_issued = Column(Integer())
    auth_required = Column(Boolean())
    issuance_date = Column(DateTime())
    expire_date = Column(DateTime())

    def __init__(self, name,amount, quantity_issued, auth_required, issuance_date, expire_date):
        self.name = name
        self.amount = amount
        self.quantity_issued = quantity_issued
        self.auth_required = auth_required
        self.issuance_date = issuance_date
        self.expire_date = expire_date

class CouponUser(Base):
    __tablename__ = "coupon_user"
    id = Column(Integer(), primary_key=True)
    user_id = Column('user_id',Integer(), ForeignKey('user.id'))
    coupon_id = Column('coupon_id',Integer(),ForeignKey('coupon.id'))
    coupon_left = Column(Integer)

    def __init__(self,user_id,coupon_id,coupon_left):
        self.user_id = user_id
        self.coupon_id = coupon_id
        self.coupon_left = coupon_left



#Base.metadata.tables["coupon"].create(bind = engine)
#Base.metadata.tables["coupon_user"].create(bind = engine)

#create coupons
#db_session.add(Coupon(name="Coupon 6", amount=500,quantity_issued=2,auth_required=False, issuance_date=datetime(2021, 3, 23), expire_date=datetime(2021, 5, 13)))
#db_session.add(Coupon(name="Coupon 7", amount=250,quantity_issued=5,auth_required=False, issuance_date=datetime(2021, 3, 23), expire_date=datetime(2021, 6, 13)))
#db_session.add(Coupon(name="Coupon 8", amount=500,quantity_issued=1,auth_required=False, issuance_date=datetime(2021, 3, 23), expire_date=datetime(2021, 4, 15)))
#db_session.add(Coupon(name="Coupon 9", amount=1000,quantity_issued=1,auth_required=True, issuance_date=datetime(2021, 3, 23), expire_date=datetime(2021, 5, 13)))
#db_session.add(Coupon(name="Coupon 10", amount=1000,quantity_issued=1,auth_required=False, issuance_date=datetime(2021, 3, 23), expire_date=datetime(2021, 6, 13)))
#db_session.commit()

def check_coupons(uid,coupon_id):
    return CouponUser.query.filter_by(user_id=uid,coupon_id=coupon_id).first()

def assign_coupons():
    u = current_user
    coupons = Coupon.query.all()
    for coupon in coupons:
        date_now = datetime.now()
        if check_coupons(u.id,coupon.id) == None and\
            coupon.expire_date > date_now and\
            date_now > coupon.issuance_date :
            if (coupon.auth_required == True and u.hkidentity_confirmed == True)\
                or coupon.auth_required == False:
                print(True)
                db_session.add(CouponUser(user_id=u.id,coupon_id=coupon.id,coupon_left=coupon.quantity_issued))
                flash(f'You receive coupon: {coupon.name}! Quantity:{coupon.quantity_issued}.')         
    db_session.commit()

def coupon_status(uid,coupon_id):
    date_now = datetime.now()
    coupon_user = check_coupons(uid,coupon_id)
    print(coupon_user)
    if coupon_user == None:
        return 5    
    coupon = Coupon.query.filter_by(id=coupon_id).first()
    if coupon.expire_date < date_now:
        return 1 #coupon is expired

    if date_now < coupon.issuance_date:
        return 2 #coupon should not yet assign and cant use now
    
    if coupon_user.coupon_left <= 0:
        return 3 # use up
    
    return 4
        


# test user
@app.before_first_request
def create_user():
    try:
        db_session.query(User).first()
    except:
        init_db()
        

@app.after_request
def set_secure_headers(response):
    secure_headers.flask(response)
    return response

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


def sendEmail(Email):
    token = serializer.dumps(Email, salt="email_confirm")
    msg = Message('Confirm Email', sender="comp3334grp2@gmail.com", recipients=[Email])
    link = url_for('confirm_email', token=token, external=True)
    msg.isBodyHtml = True
    msg.body = 'Please click this link to confirm your email:\nhttps://comp3334.herokuapp.com{}">'.format(link)
    mail.send(msg)


@app.route('/register')
def register():
    return render_template('register_user.html', page='account')


@app.route("/user_register", methods=['POST'])
def user_register():
    if request.method == 'POST':
        print("ok")
        # decrypt username, email and password
        Username = rsa.decrypt(request.form.get("encrypted_username"))
        Email = rsa.decrypt(request.form.get("encrypted_email"))
        Password = rsa.decrypt(request.form.get("encrypted_password"))
        # generate random salt
        s = "".join([string.digits, string.ascii_letters, string.punctuation])
        Salt = "".join([random.choice(s) for i in range(50)])
        # hash password
        Hashed_password = hashing.hash_value(Password, salt=Salt)
        # add user in db if email is not found in db
        if not user_datastore.find_user(email=Email):
            user_datastore.create_user(email=Email, username=Username, password=Hashed_password, salt=Salt,
                                       hkidentity_confirmed=False,role_id=1, pin_code = None,hkidentity_attempts_left=10)
            db_session.commit()
            db_session

            sendEmail(Email)

            flash("Register success!\nPlease confirm your email before login.", "success")
            return redirect(url_for('login'))
        else:
            # 在HTML文件說明中提到，get_flashed_messages會將session內的所有message全部取出，而它的形成僅在這一次的執行上下文中，因此執行一次之後消息就不見了，不需要擔心被其他登入的使用者攔到。
            flash("The email is used!", "danger")
            return redirect(url_for('register'))


@app.route('/confirm_email/', methods=['GET', 'POST'])
@app.route('/confirm_email/<token>', methods=['GET', 'POST'])
def confirm_email(token=None):
    if token != None and request.method == 'GET':
        try:
            email = serializer.loads(token, salt="email_confirm", max_age=60 * 60 * 24)
            user = user_datastore.find_user(email=email)

            if user.confirmed_at == None:
                user.confirmed_at = datetime.now()
                db_session.commit()
                flash("Email confirm success!", "success")
            else:
                flash("Email was already confirmed!", "info")

            return render_template("confirm_email.html", expired=False)
        except SignatureExpired:
            flash("The token is expired!", "danger")
            return render_template("confirm_email.html", expired=True)
    elif request.method == 'POST':
        Email = rsa.decrypt(request.form.get("encrypted_rseEmailInput"))
        sendEmail(Email)
        flash("Confirmation email resent!\nPlease confirm your email before login.", "success")
        return redirect(url_for('login'))


@app.route('/account')
@login_required
def account():
    if current_user.pin_code == None:
        set = "Set"
    else:
        set = "Reset"
    
    auth = "available"
    if current_user.hkidentity_attempts_left <= 0 or current_user.hkidentity_confirmed == True:
        auth = "inavailable"

    return render_template('account.html', page="account", username=current_user.username ,set=set, auth=auth)


@app.route('/')
def index():
    return render_template('index.html', page="none")


@app.route("/login")
def login():
    return render_template('login_user.html', page='account')


@app.route("/user_login", methods=["POST"])
def user_login():
    if request.method == "POST":
        try:
            Email = rsa.decrypt(request.form.get("encrypted_login_email"))
            Password = rsa.decrypt(request.form.get("encrypted_login_password"))

            user = user_datastore.find_user(email=Email)
            if user:
                salt = user.salt
                Hashed_password = hashing.hash_value(Password, salt=salt)
                if Hashed_password == user.password:
                    if user.confirmed_at == None:
                        flash("Please confirm your email before login.", "danger")
                        return redirect(url_for('login', page='account'))
                    else:
                        if (request.form.get("remberLogin_Check") == "True"):
                            login_user(user, remember=True)
                        else:
                            login_user(user, remember=False)
                        return redirect(url_for('account', page='account'))
                else:
                    flash("The password is incorrect!", "danger")
                    return redirect(url_for('login', page='account'))
            else:
                flash("The email is incorrect!", "danger")
                return redirect(url_for('login', page='account'))
        except Exception as error:
            flash(f"Error: {error}", "danger")
            return redirect(url_for('login', page='account'))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/pin")
@login_required
def pin():
    if current_user.pin_code == None:
        set = "Set"
    else:
        set = "Reset"
    return render_template('setpin.html', page='account',set=set)


@app.route("/set_the_pin", methods=["POST"])
@login_required
def set_the_pin():
    try:
        u = current_user
        new_pin = rsa.decrypt(request.form.get("encrypted_newPIN"))

        # generate random salt
        s = "".join([string.digits, string.ascii_letters, string.punctuation])
        pin_salt = "".join([random.choice(s) for i in range(50)])
        # hash password
        Hashed_new_pin = hashing.hash_value(new_pin, salt=pin_salt)

        if u.pin_code == None:
            u.pin_code = Hashed_new_pin
            u.pin_salt = pin_salt
            db_session.commit()
            flash("Set PIN code success!", "success")
        else:
            ori_pin = rsa.decrypt(request.form.get("encrypted_oriPIN"))
            hashed_ori_pin = hashing.hash_value(ori_pin, salt=u.pin_salt)
            if hashed_ori_pin == u.pin_code:
                u.pin_code = Hashed_new_pin
                u.pin_salt = pin_salt
                db_session.commit()
                flash("Reset PIN code success!", "success")
            else:
                flash("Incorrect Orignal PIN!","danger")

        return redirect(url_for('pin'))
    except Exception as ex:
        flash(f"Error: {ex}","danger")
        return redirect(url_for('pin'))

@app.route("/auth")
@login_required
def auth():
    return render_template('auth.html', page='account')

@app.route("/auth_handling",methods=['POST','GET'])
@login_required
def auth_handling():
    if request.method == "POST":
        try:
            if current_user.hkidentity_attempts_left <=0:
                flash("Your all authenicate attempts are used!","info")
                redirect(url_for('account'))
            if current_user.hkidentity_confirmed == True:
                flash("Your are authenicated!","info")
                redirect(url_for('account'))

            firstname = rsa.decrypt(request.form.get("encrypted_firstname"))
            lastname = rsa.decrypt(request.form.get("encrypted_lastname"))
            sex = rsa.decrypt(request.form.get("encrypted_sex"))
            birthday = rsa.decrypt(request.form.get("encrypted_birthday"))
            hkid = rsa.decrypt(request.form.get("encrypted_hkid"))
            data = HKID.query.all() 
            for person in data:
                #print(str(hkid_3des_key.decrypt(person.firstname,padding=False),encoding="utf-8"))
                #print(str(hkid_3des_key.decrypt(person.lastname,padding=False),encoding="utf-8"))
                #print(str(hkid_3des_key.decrypt(person.sex,padding=False),encoding="utf-8"))
                #print(str(hkid_3des_key.decrypt(person.birthday,padding=False),encoding="utf-8"))
                #print(str(hkid_3des_key.decrypt(person.hkid,padding=False),encoding="utf-8"))
                if firstname == str(hkid_3des_key.decrypt(person.firstname,padding=False),encoding="utf-8") and\
                    lastname == str(hkid_3des_key.decrypt(person.lastname,padding=False),encoding="utf-8") and \
                    sex == str(hkid_3des_key.decrypt(person.sex,padding=False),encoding="utf-8") and \
                    birthday == str(hkid_3des_key.decrypt(person.birthday,padding=False),encoding="utf-8") and \
                    hkid == str(hkid_3des_key.decrypt(person.hkid,padding=False),encoding="utf-8"):
                        if person.user_id == None:
                            person.user_id = current_user.id 
                            current_user.hkidentity_confirmed = True
                            db_session.commit()
                            flash('Authenication success!','success')
                        else:
                            flash('Your HKID is used!','info')
                        return redirect(url_for('account'))
            current_user.hkidentity_attempts_left -= 1
            db_session.commit()
            flash('Your data is incorrect!','danger')
            flash(f'You still have {current_user.hkidentity_attempts_left} attempt(s).','info')
            return redirect(url_for('auth'))
        except Exception as error:
            flash(f'{str(error)}','danger')
            return redirect(url_for('auth'))
        

@app.route('/select_coupon')
@login_required
def select_coupon():
    u = current_user
    if u.role_id == 2:
        return redirect(url_for('coupon'))
    else:
        assign_coupons()
        available_coupons = []
        available_coupons_quantities = []
        expired_coupons = []
        use_up_coupons = []
        coupons = Coupon.query.all()
        for coupon in coupons:
            couponStatus = coupon_status(u.id,coupon.id)
            if couponStatus == 4:
                coupon_user = CouponUser.query.filter_by(user_id=u.id,coupon_id=coupon.id).first()  
                available_coupons_quantities.append(coupon_user.coupon_left)
                available_coupons.append(coupon)
            if couponStatus == 1:
                expired_coupons.append(coupon)
            if couponStatus == 3:
                use_up_coupons.append(coupon)
        
        return render_template('coupons.html',page="qrcode",available_coupons=available_coupons\
            ,available_coupons_quantities=available_coupons_quantities,expired_coupons=expired_coupons\
                ,use_up_coupons=use_up_coupons)


@app.route('/coupon')
@app.route('/coupon/<couponID>',methods=['POST','GET'])
@login_required
def coupon(couponID=None):
    u = current_user
    if u.role_id == 2:
        return render_template('qrcode_scan.html', page='qrcode')
    if u.pin_code == None:
        flash("You should set PIN code first!", "danger")
        return render_template('qrcode.html', page='qrcode')

    coupon = check_coupons(u.id,couponID)
    if coupon.coupon_left <= 0:
        flash("You have no coupon left!", "danger")
        return render_template('qrcode.html', page='qrcode')
    return render_template('qrcode.html', page='qrcode', email=u.email, username=u.username,coupon_id=couponID,coupon_left=coupon.coupon_left)


@app.route('/ajax_coupon', methods=["POST"])
@login_required
def ajax_coupon():
    u = current_user
    if u.role_id != 1:
        return "Invalid user role", 403
    hashed = hashing.hash_value(rsa.decrypt(request.form.get("pin_code")), salt=u.pin_salt)
    print(hashed)
    coupon_id = request.form.get('coupon_id')
    if hashed == u.pin_code:
        coupon = check_coupons(u.id,coupon_id)
        return generate_coupon(u,coupon)
    return "unauthorized", 401


@app.route('/receive_coupon', methods=["POST"])
@login_required
def receive_coupon():
    try:
        t = time.time()
        token = request.form.get("token")
        u = current_user
        if u.role_id != 2:
            return "Invalid user role", 403
        coupon = decode_coupon(token)
        print(coupon)

        use_coupon_user = User.query.get(coupon["id"])
        coupon_id = coupon["coupon_id"]
        Coupon_User = check_coupons(coupon["id"],coupon["coupon_id"])

        if t > coupon["expired_at"]:
            flash("Coupon expired", "danger")
            return render_template('qrcode_scan.html', page='qrcode')
        if Coupon_User.coupon_left != coupon["coupon_left"]:
            flash("Coupon used", "danger")
            return render_template('qrcode_scan.html', page='qrcode')
        
        db_session.add(Transaction(use_coupon_user.id, u.id,coupon["name"],u.username,coupon_id))
        
        Coupon_User.coupon_left -=1
        db_session.commit()
        flash("Coupon received", "success")
        return redirect("/select_coupon")
    except Exception as ex:
        flash(f'Error:{ex}',"danger")
        flash("Invalid coupon", "danger")
        return redirect("/select_coupon")


@app.route('/transaction', methods=["GET"])
@login_required
def trasaction_list():
    u = current_user
    l = []
    if u.role_id == 1:
        l = Transaction.query.filter_by(from_user_id=u.id).all()
    elif u.role_id == 2:
        l = Transaction.query.filter_by(to_user_id=u.id).all()
 
    transactions = []
    for trasaction in l:    
        coupon = Coupon.query.filter_by(id=trasaction.coupon_id).first()
        transactions.append({
            "from_name": trasaction.from_name,
            "to_name": trasaction.to_name,
            "timestamp": trasaction.timestamp,
            "coupon_id": trasaction.coupon_id,
            "coupon_amount": coupon.amount
        })
    return render_template('transaction.html', page='record', transactions = transactions)



coupon_key = "C5C85FD23CD73E31E595938A4E995"
aes_coupon_key = b'CouponCouponCoup'

def generate_coupon(user,coupon):
    coupon = json.dumps({"id": user.id,"name":user.username,"coupon_id": coupon.coupon_id,"coupon_left":coupon.coupon_left, "expired_at": int(time.time()) + 60})
    coupon = coupon.encode('utf-8')
    cipher = AES.new(aes_coupon_key, AES.MODE_EAX)
    nonce = base64.b64encode(cipher.nonce).decode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(coupon)

    ciphertext = base64.b64encode(ciphertext).decode("utf-8")
    tag = base64.b64encode(tag).decode("utf-8")

    return base64.b64encode(json.dumps({"coupon":ciphertext, "tag":tag, "nonce":nonce}).encode('utf-8')).decode("utf-8")

def decode_coupon(token):
    decoded =base64.b64decode(token).decode('utf-8')

    ciphered_data = json.loads(decoded)

    ciphertext = base64tobyte(ciphered_data["coupon"])
    tag = base64tobyte(ciphered_data["tag"])
    nonce = base64tobyte(ciphered_data["nonce"])
    cipher = AES.new(aes_coupon_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)
    return json.loads(plaintext)

def base64tobyte(s):
    return base64.b64decode(s.encode("utf-8"))


@app.route('/checkRedeemed', methods=["POST"])
@login_required
def checkRedeemed():
    u = current_user
    coupon_id = int(request.form.get("coupon_id"))
    coupon = check_coupons(u.id,coupon_id)
    if coupon.coupon_left != int(request.form.get("coupon_left")):
        return "",200
    return "",500


if __name__ == '__main__':
    app.run(debug=False)
    csrf.init_app(app)
