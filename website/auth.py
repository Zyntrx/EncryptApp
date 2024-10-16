from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import re  
import os  
import hmac  

auth = Blueprint('auth', __name__)


PEPPER = '1633'  


def check_password_strength(password):
    if len(password) < 15:
        return 'Password must be at least 15 characters long'

    strength = {'weak': False, 'medium': False, 'strong': False}

    if re.search(r'[a-z]', password):  
        strength['weak'] = True
    if re.search(r'[A-Z]', password) and re.search(r'\d', password):  
        strength['medium'] = True
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  
        strength['strong'] = True

    if all(strength.values()):  
        return 'Strong'
    elif strength['weak'] and strength['medium']:
        return 'Medium'
    else:
        return 'Weak'


def hash_password(password):
    salt = os.urandom(16)  
    salted_peppered_password = hmac.new(PEPPER.encode(), password.encode() + salt, digestmod='sha256').hexdigest()
    hashed_password = generate_password_hash(salted_peppered_password, method='pbkdf2:sha256')
    return hashed_password, salt


def verify_password(stored_password, stored_salt, entered_password):
    salted_peppered_password = hmac.new(PEPPER.encode(), entered_password.encode() + stored_salt, digestmod='sha256').hexdigest()
    return check_password_hash(stored_password, salted_peppered_password)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if verify_password(user.password, user.salt, password):  
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords do not match.', category='error')
        else:
            strength = check_password_strength(password1)
            if strength == 'Password must be at least 15 characters long':
                flash(strength, category='error')
            elif strength == 'Weak':
                flash('Password must have 1 upper, lower case & numeric character: "a,A",(1,2,3...)', category='error')
            elif strength == 'Medium':
                flash('Must have 1 special character: !@#$%^&*.', category="error")
            else:
                hashed_password, salt = hash_password(password1)
                new_user = User(email=email, first_name=first_name, password=hashed_password, salt=salt)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
