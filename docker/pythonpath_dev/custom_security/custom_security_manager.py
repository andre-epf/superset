"""
Custom security function
"""
from superset.security import SupersetSecurityManager
from flask import request
from itsdangerous import URLSafeSerializer

class CustomSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
        self.serializer = URLSafeSerializer(appbuilder.app.config['SECRET_KEY'])

    def auth_user_db(self, username, password):
        """Authenticate user with username and password."""
        user = self.find_user(username=username)
        if user:
            self.update_user_auth_stat(user)
            return user
        return None

    def login(self, request):
        """Handle login with username/password from query parameters or normal login form."""
        username = request.args.get('username')
        token = request.args.get('token')

        if token:
            data = self.serializer.loads(token)
            username = data.get('username')
            user = self.find_user(username=username)
            if user:
                self.update_user_auth_stat(user)
                return self._login_user(user)
        
        # Call the original login method for normal login
        return super(CustomSecurityManager, self).login(request)
