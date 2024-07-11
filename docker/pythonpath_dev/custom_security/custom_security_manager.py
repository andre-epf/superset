"""
Custom security function
"""
from superset.security import SupersetSecurityManager
from itsdangerous import URLSafeSerializer
from werkzeug.security import check_password_hash

class CustomSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
        self.serializer = URLSafeSerializer(appbuilder.app.config['SECRET_KEY'])

    def auth_user_db(self, username, password):
        """Authenticate user with username and password."""
        user = self.find_user(username=username)
        if user and check_password_hash(user.password, password):
            self.update_user_auth_stat(user)
            return user
        return None

    def login(self, request):
        """Handle login with username/password from query parameters or normal login form."""
        username = request.args.get('username')
        token = request.args.get('token')
        password = request.args.get('password')

        if token:
            try:
                data = self.serializer.loads(token)
                username = data.get('username')
                user = self.find_user(username=username)
                if user:
                    self.update_user_auth_stat(user)
                    return self._login_user(user)
            except Exception as e:
                # Handle token loading exceptions
                print(f"Token loading error: {e}")
                pass
        
        if username and password:
            user = self.auth_user_db(username, password)
            if user:
                return self._login_user(user)
        
        # Fall back to the original login method for other cases
        return super(CustomSecurityManager, self).login(request)


