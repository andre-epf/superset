# custom_security.py
from flask_appbuilder import BaseView, expose
from flask import request, redirect, url_for, flash, g
from flask_appbuilder.security.decorators import has_access
from flask_babel import lazy_gettext as _
from superset.security import SupersetSecurityManager
import jwt
from werkzeug.security import check_password_hash
import logging
from flask_login import login_user


class CustomSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
        self.secret_key = appbuilder.app.config['SECRET_KEY']

    def validate_token(self, token):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.DecodeError:
            return None

    def auth_user_token(self, token):
        data = self.validate_token(token)
        if data:
            username = data.get('username')
            password = data.get('password')
            user = self.find_user(username=username)
            if user and check_password_hash(user.password, password):
                return user
        return None

class TokenLoginView(BaseView):
    route_base = "/"

    @expose('/login_with_token/')
    def login_with_token(self):
        token = request.args.get('token')
        if token:
            user = self.appbuilder.sm.auth_user_token(token)
            if user:
                login_user(user)
                flash(_("Login successful"), "success")
                return redirect('/superset/welcome/')
        flash(_("Invalid or expired token"), "danger")
        return redirect(url_for('AuthDBView.login'))
