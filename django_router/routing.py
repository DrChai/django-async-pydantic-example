import asyncio
import contextvars
from enum import IntEnum
import functools
import logging
from typing import Any, Callable, Sequence, Type
from asgiref.sync import sync_to_async
from django.db import models
from django.http import HttpRequest, HttpResponse, JsonResponse
import pydantic
# @deprecated: ErrorWrapper removed in Pydantic V2
from . import exceptions
from .types import Authentication, DjangoViewFunc, EndpointFunc, Permission, TaskFunc
from .utils import (
    EndpointParam, analyze_param, exception_handler,
    finalize_response, get_body,
    get_typed_signature, run_endpoint_function,
    validate_request_body, validate_request_params
)

logger = logging.getLogger("routing")


class Route:
    def __init__(
            self,
            path: str,
            endpoint: EndpointFunc,
            permissions: Sequence[Permission] | None = None,
            *,
            done_callbacks: Sequence[TaskFunc] = [],
            status_code: int | IntEnum = None,
            authentication_classes: Sequence[Authentication] | None = None,
            response_class: Type[HttpResponse] = JsonResponse,
            methods: list[str] | None = None,
    ) -> None:
        self.path = path
        self.endpoint = endpoint
        self.permissions = permissions or []
        self.callback_coros: list[TaskFunc] = []
        self.callback_fs: list[TaskFunc] = []
        self.path_params: list[EndpointParam] = []
        self.body_params: list[EndpointParam] = []
        self.query_params: list[EndpointParam] = []
        self.request_param: str | None = None
        self.response_class = response_class
        self.authentication_classes = authentication_classes
        if self.permissions:
            assert self.authentication_classes, \
                "authentication_classes must be specified when permissions are set. #FA001"
        for callback in done_callbacks:
            if asyncio.iscoroutinefunction(callback):
                self.callback_coros.append(callback)
            else:
                self.callback_fs.append(callback)
        if methods is None:
            methods = ["GET"]
        self.methods = methods
        if isinstance(status_code, IntEnum):
            status_code = int(status_code)
        self.status_code = status_code
        endpoint_signature = get_typed_signature(self.endpoint)
        signature_params = endpoint_signature.parameters
        self.body_param = None
        for param_name, param in signature_params.items():
            param_info = analyze_param(
                self.path,
                param_name=param_name,
                param=param,
            )
            if param_info is None:
                if issubclass(param.annotation, HttpRequest):
                    self.request_param = param_name
                continue
            if param_info.param_type == 'path':
                self.path_params.append(param_info)
            elif param_info.param_type == 'query':
                self.query_params.append(param_info)
            elif param_info.param_type == 'body':
                self.body_params.append(param_info)

    async def callback_tasks(self, rts: Any, kwargs: dict[str, Any], timeout: float = 15.0):
        aws = [asyncio.create_task(coro(rts, **kwargs)) for coro in self.callback_coros]
        done, pending = await asyncio.wait(aws, timeout=timeout, return_when=asyncio.FIRST_EXCEPTION)

        if len(pending):
            logger.error(f'Cancelling pending tasks due to timeout.\n Pending:{pending}')
            for pending_task in pending:
                pending_task.cancel()
        else:
            logger.debug(f'callback_tasks finished: {done}')

    def run_callback_aws(self, rts: Any, kwargs: dict[str, Any]):
        """
        using with heavy I/O tasks in fire-and-forget manner.
        """
        loop = asyncio.get_event_loop()
        print(f'run_callback_aws {loop}')

        def runner():
            return asyncio.run(self.callback_tasks(rts, kwargs))
        if len(self.callback_coros):
            loop.run_in_executor(None, runner)
        if len(self.callback_fs):
            ctx = contextvars.copy_context()
            for func in self.callback_fs:
                func_call = functools.partial(ctx.run, func, rts, **kwargs)
                loop.run_in_executor(None, func_call)

    async def authenticate(self, request: Type[HttpRequest]) -> tuple[Type[models.Model] | None, str | None]:
        """
        Attempt to authenticate the request using each authentication instance
        in turn.
        """
        for authentication in self.authentication_classes:
            authentication = authentication()
            try:
                user_auth_tuple = await run_endpoint_function(
                    authentication.authenticate,
                    kwargs={'request': request}
                )
                # coupling with Rest Framework's Permissions
                request.user, request.auth = user_auth_tuple if user_auth_tuple else (None, None)

            except exceptions.APIException:
                raise

            if user_auth_tuple is not None:
                return user_auth_tuple

        return None, None

    async def check_permission(self, request: Type[HttpRequest]):
        permissions = [permission() for permission in self.permissions]
        for permission in permissions:
            if not permission.has_permission(request, self):
                self.permission_denied(
                    request,
                    message=getattr(permission, 'message', None),
                    code=getattr(permission, 'code', None))

    def permission_denied(self, request: Type[HttpRequest], message=None, code=None):
        if self.authentication_classes and not getattr(request, 'user', None):
            raise exceptions.NotAuthenticated()
        raise exceptions.PermissionDenied(detail=message, code=code)

    async def check_object_permissions(self, request: Type[HttpRequest], obj: Any):
        permissions = [permission() for permission in self.permissions]
        for permission in permissions:
            if not await sync_to_async(permission.has_object_permission)(request, self, obj):
                self.permission_denied(
                    request,
                    message=getattr(permission, 'message', None),
                    code=getattr(permission, 'code', None)
                )


class Router:
    http_method_names = [
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
    ]

    def __init__(
        self,
        *,
        authentication_classes: Sequence[Authentication] | None = None,
    ) -> None:
        self.routes = {

        }
        self.default_authentication_classes = authentication_classes

    def get_urls(self):
        from django.urls import re_path as django_path
        ret = []
        for path, methods in self.routes.items():
            view = self.transform_view(methods)
            ret.append(django_path(path, view,))
        return ret

    def handle_exception(self, exc: Exception, route: Route, request: Type[HttpRequest]) -> JsonResponse:
        """
        Handle any exception that occurs, by returning an appropriate response,
        or re-raising the error.
        """
        if isinstance(exc, (exceptions.NotAuthenticated,
                            exceptions.AuthenticationFailed)):
            # WWW-Authenticate header for 401 responses, else coerce to 403
            if route.authentication_classes:
                auth_header = route.authentication_classes[0]().authenticate_header(request)
                if auth_header:
                    exc.auth_header = auth_header
                else:
                    exc.status_code = 403
        response = exception_handler(exc)

        if response is None:
            raise exc

        return response

    async def get_endpoint_params(
            self, route: Route, request: Type[HttpRequest], path_kwargs: dict[str, Any]
    ) -> tuple[dict[str, Any], list[Exception]]:
        values: dict[str, Any] = {}
        errors: list[Exception] = []
        user, auth = await route.authenticate(request)
        await route.check_permission(request)
        request.check_object_permissions = functools.partial(route.check_object_permissions, request)
        path_values, path_errors = validate_request_params(
            route.path_params, path_kwargs
        )
        query_values, query_errors = validate_request_params(
            route.query_params, request.GET
        )
        if route.request_param:
            values[route.request_param] = request
        if len(route.body_params) > 0:
            body = get_body(request)
            body_values, body_errors = await validate_request_body(
                required_params=route.body_params, received_body=body
            )
            values |= body_values
            errors += body_errors
        values |= path_values
        values |= query_values

        errors += path_errors + query_errors
        return values, errors

    def transform_view(self, methods: dict[str, Route]) -> DjangoViewFunc:
        async def view(request: Type[HttpRequest], *args: Any, **kwargs: Any) -> Type[HttpResponse]:
            if request.method in methods:
                route = methods[request.method]
                try:
                    endpoint_kwargs = {}
                    endpoint_kwargs |= kwargs
                    validated_kwargs, errors = await self.get_endpoint_params(route, request, kwargs)
                    if errors:
                        raise pydantic.ValidationError(errors, pydantic.BaseModel)
                    raw_response = await run_endpoint_function(route.endpoint, kwargs=validated_kwargs)
                    route.run_callback_aws(raw_response, validated_kwargs)
                    return finalize_response(raw_response)
                except Exception as exc:
                    return self.handle_exception(exc, route, request)
            else:
                method_exec = exceptions.MethodNotAllowed(request.method)
                return exception_handler(method_exec)
        view.csrf_exempt = True
        return view

    def api_route(
            self,
            path: str,
            *,
            permissions: Sequence[Permission] | None = None,
            authentication_classes: Sequence[Authentication] | None = None,
            async_tasks: Sequence[TaskFunc] | None = None,
            methods: list[str] | None = None,
            status_code: int | None = None,
            response_class: Type[HttpResponse] = JsonResponse,
    ) -> Callable[[EndpointFunc], EndpointFunc]:
        def decorator(func: EndpointFunc) -> EndpointFunc:
            route = Route(
                path, func,
                permissions=permissions,
                status_code=status_code,
                methods=methods,
                done_callbacks=async_tasks or [],
                response_class=response_class,
                authentication_classes=authentication_classes or self.default_authentication_classes
            )
            methods_dict = self.routes.setdefault(path, {})
            methods_dict |= {methods[0]: route}
            return func

        return decorator

    def __getattr__(self, attr):
        if attr.lower() in self.http_method_names:
            def decorator_ref(
                    path: str,
                    *,
                    permissions: Sequence[Permission] | None = None,
                    authentication_classes: Sequence[Authentication] | None = None,
                    response_class: Type[HttpResponse] = JsonResponse,
                    async_tasks: Sequence[TaskFunc] | None = None,
                    status_code: int | None = None,
            ) -> Callable[[EndpointFunc], EndpointFunc]:
                return self.api_route(
                    path=path,
                    permissions=permissions,
                    authentication_classes=authentication_classes,
                    async_tasks=async_tasks,
                    methods=[attr.upper()],
                    status_code=status_code,
                    response_class=response_class,
                )
            setattr(self, attr, decorator_ref)
            return decorator_ref
