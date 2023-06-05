from typing import Callable
from django.http import HttpRequest, JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from .utils import exception_handler, run_endpoint_function

from .rest_framework import authentication
from .rest_framework import permissions
from . import exceptions


class AsyncAPIView(View):
    authentication_classes = (authentication.BasicAuthentication,)
    permission_classes = (permissions.AllowAny,)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.request = None

    @classmethod
    def as_view(cls, **initkwargs):
        view = super().as_view(**initkwargs)
        view.cls = cls
        view.initkwargs = initkwargs

        # Note: session based authentication is explicitly CSRF validated,
        # all other authentication is CSRF exempt.
        return csrf_exempt(view)

    async def http_method_not_allowed(self, request, *args, **kwargs):
        raise exceptions.MethodNotAllowed(request.method)

    def permission_denied(self, request, message=None, code=None):

        if self.get_authenticators() and not request.successful_authenticator:
            raise exceptions.NotAuthenticated()
        raise exceptions.PermissionDenied(detail=message, code=code)

    async def dispatch(self, request: HttpRequest, *args, **kwargs) -> JsonResponse:
        try:
            await self.initial(request, *args, **kwargs)
            if request.method.lower() in self.http_method_names:
                handler = getattr(
                    self, request.method.lower(), self.http_method_not_allowed
                )
            else:
                handler = self.http_method_not_allowed
            response = await handler(request, *args, **kwargs)
            self.request = request
        except Exception as exc:
            response = self.handle_exception(exc)
        return response

    def get_authenticators(self):
        """
        Instantiates and returns the list of authenticators that this view can use.
        """
        return [auth() for auth in self.authentication_classes]

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        return [permission() for permission in self.permission_classes]

    def get_authenticate_header(self, request: HttpRequest) -> str:
        """
        If a request is unauthenticated, determine the WWW-Authenticate
        header to use for 401 responses, if any.
        """
        authenticators = self.get_authenticators()
        if authenticators:
            return authenticators[0].authenticate_header(request)

    def get_exception_handler(self) -> Callable[[Exception], JsonResponse | None]:
        return exception_handler

    def handle_exception(self, exc: Exception) -> JsonResponse:

        if isinstance(exc, (exceptions.NotAuthenticated,
                            exceptions.AuthenticationFailed)):
            # WWW-Authenticate header for 401 responses, else coerce to 403
            auth_header = self.get_authenticate_header(self.request)

            if auth_header:
                exc.auth_header = auth_header
            else:
                exc.status_code = 403

        exception_handler = self.get_exception_handler()
        response = exception_handler(exc)

        if response is None:
            raise exc

        return response

    async def initial(self, request: HttpRequest, *args, **kwargs) -> None:
        """
        Runs anything that needs to occur prior to calling the method handler.
        """

        # Ensure that the incoming request is permitted
        await self.perform_authentication(request)
        self.check_permissions(request)
        # self.check_throttles(request)

    async def perform_authentication(self, request: HttpRequest) -> None:

        for authenticator in self.get_authenticators():
            try:
                request.data = request.POST
                user_auth_tuple = await run_endpoint_function(
                    authenticator.authenticate,
                    kwargs={'request': request}
                )
            except exceptions.APIException:
                raise

            if user_auth_tuple is not None:
                request._authenticator = authenticator
                request.user, request.auth = user_auth_tuple
                return
        request.user, request.auth = None, None

    def check_permissions(self, request: HttpRequest) -> None:

        for permission in self.get_permissions():
            if not permission.has_permission(request, self):
                if self.get_authenticators() and not hasattr(request, '_authenticator'):
                    raise exceptions.NotAuthenticated()
                raise exceptions.PermissionDenied(
                    detail=getattr(permission, 'message', None),
                    code=getattr(permission, 'code', None))

    async def check_object_permissions(self, request, obj):

        for permission in self.get_permissions():
            if not await run_endpoint_function(
                permission.has_object_permission,
                kwargs={'request': request, 'view': self, 'obj': obj}
            ):
                self.permission_denied(
                    request,
                    message=getattr(permission, 'message', None),
                    code=getattr(permission, 'code', None)
                )
