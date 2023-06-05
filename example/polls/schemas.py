from datetime import datetime
from functools import reduce
from typing import Any
from django.db.models import Manager
from django.db.models.fields.files import ImageFieldFile
from django.utils import timezone
from pydantic import BaseModel, Field, NonNegativeInt, constr
from pydantic.utils import GetterDict


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


class ChoicePost(BaseModel):
    choice_text: constr(max_length=200)
    votes: NonNegativeInt

    class Config:
        orm_mode = True
        getter_dict = ModelGetterDict


class QuestionPost(BaseModel):
    pub_date: datetime | None = Field(default_factory=timezone.now)
    question_text: constr(max_length=200)
    choice_set: list[ChoicePost]

    class Config:
        orm_mode = True
        getter_dict = ModelGetterDict


class QuestionOut(QuestionPost):
    id: int


class QuestionListOut(BaseModel):
    data: list[QuestionOut]


class QuestionUpdate(BaseModel):
    question_text: constr(max_length=20)
    pub_date: datetime | None

    class Config:
        orm_mode = True
        getter_dict = ModelGetterDict
