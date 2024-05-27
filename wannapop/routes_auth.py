from flask import Blueprint, redirect, url_for, render_template, flash, request, jsonify
from flask_login import current_user, login_required, login_user, logout_user
from . import login_manager, mail_manager, logger, db_manager as db
from .forms import LoginForm, RegisterForm, ResendForm
from .helper_role import notify_identity_changed, Role
from .models import User
import secrets
from markupsafe import Markup
from datetime import datetime
from flask_mail import Message

# Blueprint
auth_bp = Blueprint("auth_bp", __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main_bp.init"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        logger.debug(f"Usuari {email} intenta autenticar-se")

        user = load_user(email)
        if user and user.check_password(password):
            if not user.verified:
                logger.warning(f"Usuari {email} no s'ha autenticat correctament")
                flash("Revisa el teu email i verifica el teu compte", "error")
                return redirect(url_for("auth_bp.login"))
            
            logger.info(f"Usuari {email} s'ha autenticat correctament")

            login_user(user)
            notify_identity_changed()
            return redirect(url_for("main_bp.init"))

        flash("Error d'usuari i/o contrasenya", "error")
        return redirect(url_for("auth_bp.login"))
    
    return render_template('auth/login.html', form = form)

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main_bp.init"))

    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User()
        form.populate_obj(new_user)
        new_user.role = Role.wanner
        new_user.verified = False
        new_user.email_token = secrets.token_urlsafe(20)

        if not new_user.save():
            logger.error(f"No s'ha inserit l'usuari/a {new_user.email} a BD")
            flash("Nom d'usuari/a i/o correu electrònic duplicat", "danger")
        else:
            logger.info(f"Usuari {new_user.email} s'ha registrat correctament")
            try:
                mail_manager.send_register_email(new_user.name, new_user.email, new_user.email_token)
                flash("Revisa el teu correu per verificar-lo", "success")
            except:
                logger.warning(f"No s'ha enviat correu de verificació a l'usuari/a {new_user.email}")
                flash(Markup("No hem pogut enviar el correu de verificació. Prova-ho més tard <a href='/resend'>aquí</a>"), "danger")

            return redirect(url_for("auth_bp.login"))
    
    return render_template('auth/register.html', form = form)

@auth_bp.route("/verify/<name>/<token>")
def verify(name, token):
    user = User.get_filtered_by(name=name)
    if user and user.email_token == token:
        user.verified = True
        user.email_token = None
        user.update()
        flash("Compte verificat correctament", "success")
    else:
        flash("Error de verificació", "error")
    return redirect(url_for("auth_bp.login"))

@auth_bp.route("/resend", methods=["GET", "POST"])
def resend():
    if current_user.is_authenticated:
        return redirect(url_for("main_bp.init"))

    form = ResendForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.get_filtered_by(email=email)
        if user:
            if user.verified:
                flash("Aquest compte ja està verificat", "error")
            else:
                mail_manager.send_register_email(user.name, user.email, user.email_token)
                flash("Revisa el teu correu per verificar-lo", "success")
        else:
            flash("Aquest compte no existeix", "error")
        return redirect(url_for("auth_bp.login"))
    else:
        return render_template('auth/resend.html', form = form)

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("T'has desconnectat correctament", "success")
    return redirect(url_for("auth_bp.login"))

@login_manager.user_loader
def load_user(email):
    if email is not None:
        user = User.get_filtered_by(email=email)
        if user:
            return user
    return None

@login_manager.unauthorized_handler
def unauthorized():
    flash("Autentica't o registra't per accedir a aquesta pàgina", "error")
    return redirect(url_for("auth_bp.login"))

@auth_bp.route('/request-token', methods=['POST'])
def request_token():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        user.generate_token()
        token_url = url_for('auth_bp.login_with_token', token=user.one_time_token, _external=True)
        msg = Message('Your Login Token', recipients=[email])
        msg.body = f'Use this link to log in: {token_url}'
        mail_manager.send(msg)
        return jsonify({"message": "A login token has been sent to your email."}), 200
    return jsonify({"message": "Email not found."}), 404

@auth_bp.route('/login/<token>', methods=['GET'])
def login_with_token(token):
    user = User.query.filter_by(one_time_token=token).first()
    if user and user.token_expiration > datetime.utcnow():
        user.one_time_token = None
        user.token_expiration = None
        db.session.commit()
        login_user(user)
        notify_identity_changed()
        return jsonify({"message": "Successfully logged in!"}), 200
    return jsonify({"message": "Invalid or expired token."}), 401
