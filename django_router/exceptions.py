from http import HTTPStatus
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _


class APIException(Exception):
    status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    default_detail = _('A server error occurred.')
    default_code = 'error'

    def __init__(self, detail=None, code=None):
        if detail is None:
            detail = self.default_detail
        if code is None:
            code = self.default_code
        self.detail = detail

    def __str__(self):
        return str(self.detail)


class NotFound(APIException):
    status_code = HTTPStatus.NOT_FOUND
    default_detail = _('Not found.')
    default_code = 'not_found'


class MethodNotAllowed(APIException):
    status_code = HTTPStatus.METHOD_NOT_ALLOWED
    default_detail = _('Method "{method}" not allowed.')
    default_code = 'method_not_allowed'

    def __init__(self, method, detail=None, code=None):
        if detail is None:
            detail = force_str(self.default_detail).format(method=method)
        super().__init__(detail, code)


class AuthenticationFailed(APIException):
    status_code = HTTPStatus.UNAUTHORIZED
    default_detail = _('Incorrect authentication credentials.')
    default_code = 'authentication_failed'


class NotAuthenticated(APIException):
    status_code = HTTPStatus.UNAUTHORIZED
    default_detail = _('Authentication credentials were not provided.')
    default_code = 'not_authenticated'


class PermissionDenied(APIException):
    status_code = HTTPStatus.FORBIDDEN
    default_detail = _('You do not have permission to perform this action.')
    default_code = 'permission_denied'


class UnsupportedMediaType(APIException):
    status_code = HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    default_detail = _('Unsupported media type "{media_type}" in request.')
    default_code = 'unsupported_media_type'

    def __init__(self, media_type, detail=None, code=None):
        if detail is None:
            detail = force_str(self.default_detail).format(media_type=media_type)
        super().__init__(detail, code)
