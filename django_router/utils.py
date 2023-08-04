import asyncio
from asgiref.sync import sync_to_async
import codecs
from copy import deepcopy
from dataclasses import dataclass, is_dataclass
import inspect
from io import BytesIO
import json
import re
from typing import Annotated, Any, ForwardRef, Sequence, Type
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from pydantic.fields import FieldInfo, Field
from pydantic._internal._typing_extra import eval_type_lenient
from pydantic import BaseModel, ValidationError, TypeAdapter
from pydantic_core import PydanticUndefined

from .types import EndpointFunc
from . import exceptions


def get_missing_field_error(loc: tuple[str, ...]) -> dict[str, Any]:
    error = ValidationError.from_exception_data(
        "Field required", [{"type": "missing", "loc": loc, "input": {}}]
    ).errors()[0]
    error["input"] = None
    return error  # type: ignore[return-value]


def _regenerate_error_with_loc(
    *, errors: Sequence[Any], loc_prefix: tuple[str | int, ...]
) -> list[dict[str, Any]]:
    updated_loc_errors: list[Any] = [
        {**err, "loc": loc_prefix + err.get("loc", ())}
        for err in errors
    ]

    return updated_loc_errors


@dataclass
class EndpointParam:
    param_name: str
    annotation: Type[Any]
    field_info: FieldInfo

    def __post_init__(self):
        self._type_adapter: TypeAdapter[Any] = TypeAdapter(
            Annotated[self.field_info.annotation, self.field_info]
        )

    def validate(
        self,
        value: Any,
        values: dict[str, Any] = {},  # noqa: B006
        *,
        loc: tuple[int | str, ...] = (),
    ) -> tuple[Any, list[dict[str, Any]] | None]:
        try:
            return (
                self._type_adapter.validate_python(value, from_attributes=True),
                None,
            )
        except ValidationError as exc:
            return None, _regenerate_error_with_loc(
                errors=exc.errors(), loc_prefix=loc
            )

    @property
    def alias(self) -> str:
        return self.field_info.alias or self.name

    @property
    def default(self) -> Any | None:
        return self.field_info.default

    @property
    def required(self) -> bool:
        return self.field_info.default in (PydanticUndefined,)

    @property
    def kind(self):
        issubclass(self.annotation, BaseModel)

    @property
    def param_type(self):
        return self.field_info.json_schema_extra['param_type']


_PATH_PARAMETER_COMPONENT_RE = r"<(?:(?P<converter>[^>:]+):)?(?P<parameter>[^>]+)>"


def get_path_param_names(path: str) -> set[str]:
    return set(match.group('parameter') for match in re.finditer(_PATH_PARAMETER_COMPONENT_RE, path))


def is_scalar(param: inspect.Parameter) -> bool:
    if any([
        issubclass(param.annotation, BaseModel),
        issubclass(param.annotation, (dict, list, set, tuple)),
        is_dataclass(param.annotation)
    ]):
        return False
    return True


def analyze_param(
        path: str,
        *,
        param_name: str,
        param: inspect.Parameter,
) -> EndpointParam | None:
    is_path_param = param_name in get_path_param_names(path)
    field_info = None
    field = None
    if isinstance(param.default, FieldInfo):  # foo: = Field(..., discriminator='pet_type')
        assert 'param_type' in param.default.json_schema_extra, 'unidentified FieldInfo. #FE005'
        field_info = param.default
    if issubclass(param.annotation, (HttpRequest,)):
        assert (field_info is None), f"Cannot specify annotation for {param.annotation!r}. #FE003"
    elif field_info is None:
        default_value = param.default if param.default is not inspect.Signature.empty else PydanticUndefined
        if is_path_param:
            assert is_scalar(param), 'wrong type. #FE004'
            field_info = Field(param_type='path')
        elif is_scalar(param):
            field_info = Field(param_type='query', default=default_value)
        else:
            field_info = Field(param_type='body', default=default_value)
        annotation = param.annotation if param.annotation is not inspect.Signature.empty else Any
        field = EndpointParam(
            param_name=param_name,
            annotation=annotation,
            field_info=field_info,
        )
    return field


def get_typed_annotation(annotation: Any, globalns: dict[str, Any]) -> Any:
    if isinstance(annotation, str):
        annotation = ForwardRef(annotation)
        annotation = eval_type_lenient(annotation, globalns, globalns)
    return annotation


def get_typed_signature(call: EndpointFunc) -> inspect.Signature:
    signature = inspect.signature(call)
    globalns = getattr(call, "__globals__", {})
    typed_params = [
        inspect.Parameter(
            name=param.name,
            kind=param.kind,
            default=param.default,
            annotation=get_typed_annotation(param.annotation, globalns),
        )
        for param in signature.parameters.values()
    ]
    typed_signature = inspect.Signature(typed_params)
    return typed_signature


async def run_endpoint_function(endpoint: EndpointFunc, *, kwargs: dict[str, Any]) -> Any:
    assert endpoint is not None, "endpoint must be a function"
    is_coroutine = asyncio.iscoroutinefunction(endpoint)
    if is_coroutine:
        return await endpoint(**kwargs)
    else:
        return await sync_to_async(endpoint)(**kwargs)


def content_type(request: Type[HttpRequest]):
    meta = request.META
    return meta.get('CONTENT_TYPE', meta.get('HTTP_CONTENT_TYPE', ''))


def get_body(request: Type[HttpRequest]) -> Any:
    ct = content_type(request)
    content_length: int = 0
    try:
        content_length = int(
            request.META.get('CONTENT_LENGTH', request.META.get('HTTP_CONTENT_LENGTH', 0))
        )
    except (ValueError, TypeError):
        return None
    decoded_stream = codecs.getreader("utf-8")(BytesIO(request.body))
    if ct == 'application/json':
        try:
            return json.load(decoded_stream) if content_length else {}
        except json.JSONDecodeError as exc:
            raise exceptions.APIException({"detail": [
                {
                    "type": "json_invalid",
                    "loc": ("body", exc.pos),
                    "msg": "JSON decode error",
                    "input": {},
                    "ctx": {"error": exc.msg},
                }
            ]})
    elif ct == 'form-data':  # TODO: need a pr
        raise NotImplementedError
    elif ct == 'application/x-www-form-urlencoded':
        raise NotImplementedError
    return {}


async def validate_request_body(
        required_params: list[EndpointParam],
        received_body: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[Exception]]:
    errors: list[Exception] = []
    values: dict[str, Any] = {}
    if required_params:
        nested = len(required_params) == 1
        if nested:
            received_body = {required_params[0].param_name: received_body}
        for field in required_params:
            if nested:
                loc = ("body",)
            else:
                loc = ("body", field.param_name)

            value: Any | None = None
            if received_body is not None:
                try:
                    value = received_body.get(field.param_name)
                except AttributeError:
                    errors.append(get_missing_field_error(loc=loc))
                    continue
            if (
                    value is None
            ):
                if field.required:
                    errors.append(get_missing_field_error(loc=loc))
                else:
                    values[field.param_name] = deepcopy(field.default)
                continue
            v_, errors_ = field.validate(value, values, loc=loc)

            if isinstance(errors_, Exception):
                errors.append(errors_)
            else:
                values[field.param_name] = v_
        return values, errors


def validate_request_params(
        required_params: list[EndpointParam],
        received_params: dict[str, Any],
) -> tuple[dict[str, Any], list[Exception]]:
    errors: list[Exception] = []
    values: dict[str, Any] = {}
    for param in required_params:
        value = received_params.get(param.param_name)
        if value is None:
            if param.required:
                errors.append(
                    get_missing_field_error(loc=(param.param_type, param.param_name))
                )
            else:
                values[param.param_name] = deepcopy(param.default)
            continue
        v_, errors_ = param.validate(
            value, values, loc=(param.param_type, param.alias)
        )
        if isinstance(errors_, Exception):
            errors.append(errors_)
        # elif isinstance(errors_, list):
        #     errors.extend(errors_)
        else:
            values[param.param_name] = v_
    return values, errors


def exception_handler(exc):

    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, PermissionDenied):
        exc = exceptions.PermissionDenied()
    elif isinstance(exc, ValidationError):
        data = {'detail': exc.errors()}
        return JsonResponse(data, status=400)
    if isinstance(exc, exceptions.APIException):
        headers = {}
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header
        if isinstance(exc.detail, dict):
            data = exc.detail
        else:
            data = {'detail': exc.detail}
        # better handle it while being aware of the potential bugs
        # set_rollback()

        return JsonResponse(data, status=exc.status_code, headers=headers)

    return None


def finalize_response(resp: Any) -> Type[HttpResponse]:
    def encode_data(obj: Any) -> Any:
        rts = obj
        if isinstance(obj, BaseModel):
            rts = obj.dict()
        if isinstance(obj, dict):
            rts = {}
            for key, value in obj.items():
                serialize_value = encode_data(value)
                rts[key] = serialize_value
        if isinstance(obj, Sequence) and not isinstance(obj, str):
            rts = []
            for item in obj:
                rts.append(
                    encode_data(item,)
                )
        return rts
    if isinstance(resp, HttpResponse):
        return resp
    json_resp = encode_data(resp)
    return JsonResponse(json_resp)
