from typing import Any, Callable, TypeVar, Type, ParamSpec

from django.http import HttpRequest, HttpResponse
from .rest_framework.authentication import BaseAuthentication
from .rest_framework.permissions import BasePermission

TaskParams = ParamSpec("TaskParams")
EndpointFunc = TypeVar("EndpointFunc", bound=Callable[..., Any])
TaskFunc = Callable[TaskParams, Any]
DjangoViewFunc = TypeVar("DjangoViewFunc", bound=Callable[[Type[HttpRequest], Any, Any], Type[HttpResponse]])
Authentication = Type[BaseAuthentication]
Permission = Type[BasePermission]
