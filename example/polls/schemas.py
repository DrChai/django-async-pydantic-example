from datetime import datetime
from functools import reduce
from typing import Annotated, Any, TypeVar
from typing_extensions import deprecated
from django.db.models import Manager
from django.db.models.fields.files import ImageFieldFile
from django.utils import timezone
from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt, constr, WrapValidator
from pydantic.utils import GetterDict


# @deprecated used in Pydantic V1
@deprecated('GetterDict is removed in Pydantic V2')
class ModelGetterDict(GetterDict):

    def get(self, key: Any, default: Any = None) -> Any:
        if "__" in key:
            # Allow double underscores aliases: `first_name: str = Field(alias="user__first_name")`
            keys_map = key.split("__")
            attr = reduce(lambda a, b: getattr(a, b, default), keys_map, self._obj)
        else:
            attr = getattr(self._obj, key, None)

        is_manager = issubclass(attr.__class__, Manager)

        if is_manager:
            attr = list(attr.all())
        elif issubclass(attr.__class__, ImageFieldFile):
            attr = attr.url if attr.name else None
        return attr


def validate_relatedfields(v, handler):
    related_fields = v
    if isinstance(v, Manager):
        # we don't want to bother with further validation, just return the new value
        related_fields = list(v.all())
    return handler(related_fields)


RelatedFieldType = TypeVar('RelatedFieldType', bound='BaseModel')
RelatedFields = Annotated[list[RelatedFieldType], WrapValidator(validate_relatedfields)]


class ChoicePost(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    choice_text: constr(max_length=200)
    votes: NonNegativeInt


class QuestionPost(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    pub_date: datetime | None = Field(default_factory=timezone.now)
    question_text: constr(max_length=200)
    choice_set: RelatedFields[ChoicePost]


class QuestionOut(QuestionPost):
    id: int


class QuestionListOut(BaseModel):
    data: list[QuestionOut]


class QuestionUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    question_text: constr(max_length=20)
    pub_date: datetime | None
