"""
Custom security function
"""
import logging
from flask_babel import gettext as __
from superset.security import SupersetSecurityManager
from superset.exceptions import (
    SupersetSecurityException
)
from superset.errors import ErrorLevel, SupersetError, SupersetErrorType
from itsdangerous import URLSafeSerializer
from werkzeug.security import check_password_hash

logger = logging.getLogger(__name__)

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
            except Exception as message:
                logger.warning("Token loading error: (%s)", message)
                raise SupersetSecurityException(
                    SupersetError(
                        error_type=SupersetErrorType.DATABASE_SECURITY_ACCESS_ERROR,
                        message=__(
                            f"You may have an error in your auto login link. {message}"
                        ),
                        level=ErrorLevel.ERROR,
                    )
                )
        
        if username and password:
            user = self.auth_user_db(username, password)
            if user:
                return self._login_user(user)
        
        return super(CustomSecurityManager, self).login(request)


