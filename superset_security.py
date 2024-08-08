# custom_security.py
import os
from flask_appbuilder import BaseView, expose
from flask import request, redirect, url_for, flash, current_app
from flask_babel import lazy_gettext as _
from superset.security import SupersetSecurityManager
import jwt
import logging
from flask_login import login_user
from typing import Dict, List, Tuple
from flask_appbuilder.security.sqla.models import PermissionView, Permission, ViewMenu, Role
from sqlalchemy.orm import contains_eager
from superset.security.guest_token import (
    GuestToken,
    GuestUser
)

class CustomSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)

    def validate_token(self, token):
        try:
            payload = jwt.decode(token, os.getenv("SUPERSET_SECRET_KEY"), algorithms=['HS256'])
            return payload
        
        except jwt.ExpiredSignatureError as message:
            logging.debug(f"Token expired: {message}")
            return None
        
        except jwt.DecodeError as message:
            logging.debug(f"Token decoding error: {message}")
            return None
        
        except jwt.InvalidSignatureError as message:
            logging.debug(f"Invalid signature: {message}")
            return None

    def auth_user_token(self, token):
        data = self.validate_token(token)
        if data:
            username = data.get('username')
            user = self.find_user(username=username)
            if user:
                return user
            
        return None
    
    def get_user_roles_permissions(self, user) -> Dict[str, List[Tuple[str, str]]]:
        """
        Fetch all roles and permissions for a specific user with additional validation.
        """
        if not user.roles:
            raise AttributeError("User object does not have roles")

        # Initialize result dictionary
        result: Dict[str, List[Tuple[str, str]]] = {}
        db_roles_ids = []

        for role in user.roles:

            if role is None or not hasattr(role, 'name'):
                raise ValueError("Role is invalid or does not have a name")

            result[role.name] = []

            if role.name in super().builtin_roles:
                for permission in super().builtin_roles[role.name]:
                    result[role.name].append((permission[1], permission[0]))
            else:
                db_roles_ids.append(role.id)

        # Query permission views for database roles
        permission_views = (
            self.appbuilder.get_session.query(PermissionView)
            .join(Permission)
            .join(ViewMenu)
            .join(PermissionView.role)
            .filter(Role.id.in_(db_roles_ids))
            .options(contains_eager(PermissionView.permission))
            .options(contains_eager(PermissionView.view_menu))
            .options(contains_eager(PermissionView.role))
        ).all()

        for permission_view in permission_views:
            for role_item in permission_view.role:
                if role_item.name in result:
                    result[role_item.name].append(
                        (
                            permission_view.permission.name,
                            permission_view.view_menu.name,
                        )
                    )

        return result
    
    def get_guest_user_from_token(self, token: GuestToken) -> GuestUser:
        return self.guest_user_cls(
            token=token,
            roles=[self.find_role("Public")],
        )


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
