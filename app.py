from user.forms import Signup, Login, Forgot_pass,Verify
from flask import Flask, url_for, request, render_template, jsonify, json, flash, redirect, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_mail import Mail
from flask_mail import Message
import jwt
import datetime
import time
import secrets
import json
app = Flask(__name__)
with open('./imp.json') as important:
    imp = json.load(important)['params']
app.config['SECRET_KEY'] = 'f16bbd80d59404'
app.config["MONGO_URI"] = "mongodb://localhost:27017/apptware"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT='465',
    MAIL_USE_SSL=True,
    MAIL_USERNAME=imp['account'],
    MAIL_PASSWORD=imp['password']
)
Session(app)
bcrypt = Bcrypt(app)
mongodb_client = PyMongo(app)
mail = Mail(app)
db = mongodb_client.db




@app.route('/', methods=['GET', 'POST'])
def ses():
    session['attempt'] = 0
    return redirect(url_for('home'))


@app.route("/login", methods=['GET', 'POST'])
def home():
    form_login = Login()
    values = db.flask_login.find_one({'email': form_login.email.data})
    print(form_login.data)
    if request.method == 'POST':
        print(values)
        time_passed=values['time']
        passwd = values['password']
        if (bcrypt.check_password_hash(passwd, form_login.password.data) and time_passed==0):
            flash("Yes!Correct login", "success")
            token=jwt.encode({
                'email':values['email'],
                'password':values['password'],
                'time':str(datetime.datetime.utcnow())
            },
             app.config['SECRET_KEY'])

            return (jsonify({'token':token.decode('utf-8')}))

        elif time_passed!=0:
            time_remaining=time.time()
            if time_remaining-values['time'] >= 86400:
                token=jwt.encode({
                'email':values['email'],
                'password':values['password'],
                'time':str(datetime.datetime.utcnow())
            },
             app.config['SECRET_KEY'])

                return (jsonify({'token':token.decode('utf-8')}))
            else:
                remain=86400+values['time']-time_remaining
                return jsonify({"Time till retry is :":str(time.strftime("%H:%M:%S", time.gmtime(remain)))})

        else:
            flash("Incorrect", "warning")
            session['attempt'] += 1
            # print(session['counter'])
            if session['attempt'] >= 3:
                session['attempt'] = 0
                flash("You have failed 3 times!You cant have any more tries", 'danger')
                db.flask_login.update_one({"email":form_login.email.data}, {"$set":{"time":time.time()}})
                return ("You have tried more than 3 times!")
            incorrect={
                "Number of tries remaining":3-session['attempt']
            }
            return jsonify(incorrect)
            

    # return (render_template('home.html', form=form_login))
    return ("Welcome!")


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = Signup()
    if form.validate():
        err=form.errors.items()
        
        if(db.flask_login.find_one({'email': form.email.data})):
            flash(
                "An account already exists with the same email!Try another one", 'danger')
            n={
                'Warning':"An account already exists with the same email!Try another one"
            }
            return jsonify(n)
        else:
            # print(form.password.data)
            password = bcrypt.generate_password_hash(
                form.password.data).decode('UTF-8')
            db.flask_login.insert_one(
                {'name': form.name.data, 'password': password, 'email': form.email.data, 'phone': form.phone.data,'time':0})
            flash(
                f"The account submission is done for {form.name.data}", 'success')
            # return (redirect(url_for('home')))
            account=form.data
            return (jsonify(account))
    # return (render_template('signup.html', form=form))
    if form.errors:
        key,value="",""
        for k,val in form.errors.items():
            key=k
            value=val
        return jsonify({'Error':"Error encounter","Value at":key,"Error type":val})
    else:
        return 


@app.route("/forgot-pass", methods=['GET', 'POST'])
def forpass():
    form = Forgot_pass()
    if request.method == 'POST':
        if form.validate_on_submit():
            if(db.flask_login.find_one({'email': form.email.data})):
                print([form.email.data])
                msg = Message('This is your verification code!!',
                              sender=imp['account'], recipients=[form.email.data])
                password_length = 13
                password_to_email = (secrets.token_urlsafe(password_length))
                msg.body = f"Here is your verification code...use it wise boi/gorl.Verify: {password_to_email}"
                mail.send(msg)
                db.flask_login.find_one_and_update({'email': form.email.data}, {"$set":{
                                                   'verification': password_to_email}})
                # return redirect(url_for('password_change'))
                msg={
                    'Message':"Kindly check your email for the verification Code!"
                }
                return jsonify(msg)
            else:
                # flash("INCORRECT EMAIL! PLEASE FIRST REGISTER!!", 'danger')
                return ("INCORRECT EMAIL!! REGISTER FIRST")
            # msg=Message()

    return (render_template('forgot_pass.html', form=form))


@app.route('/password-change',methods=['GET','POST'])
def password_change():
    form=Verify()
    if request.method=='POST':
        verification=form.verify.data
        if (db.flask_login.find({'verification':verification})):
            password = bcrypt.generate_password_hash(
                    form.pschange.data).decode('UTF-8')
            db.flask_login.update_one({'verification':verification},{"$set":{'password':password}})
            flash("Password changed Successful!",'success')
            # return redirect(url_for('home'))
            return ('The password has been changed!')
        else:
            flash("WRONG VERIFICATION GOODBYE!",'danger')
            # return redirect(url_for('home'))
            return ('Wrong Verification!')
    return render_template('pass_forgot.html',form=form)


if __name__ == '__main__':
    app.run(debug=True, port="7000", threaded='True')
