
from asgiref.sync import sync_to_async
from django.db import transaction
from django.db.models import QuerySet
from django.http import Http404, JsonResponse
from django_router.rest_framework import authentication, permissions
from django_router import AsyncAPIView, get_body
from . import schemas
from .models import Question


async def aget_object_or_404(queryset: QuerySet, *args, **kwargs):
    try:
        return await queryset.aget(*args, **kwargs)
    except (queryset.model.DoesNotExist, TypeError, ValueError,):
        raise Http404(
            f"No {queryset.model._meta.object_name} matches the given query."
        )


# in Django Restful Framework style.
class AsyncPollsList(AsyncAPIView):
    async def get_queryset(self) -> list[Question]:
        q = self.request.GET.get('q')
        qs = Question.objects.prefetch_related('choice_set',).all()
        if q:
            qs = qs.filter(question_text__icontains=q)
        return [entry async for entry in qs]

    async def get(self, request, *args, **kwargs) -> JsonResponse:
        queryset = await self.get_queryset()
        data = schemas.QuestionListOut(data=queryset)
        return JsonResponse(data.dict())

    @sync_to_async
    def atomic_operation(self, question: schemas.QuestionPost) -> Question:
        new_data = question.dict()
        with transaction.atomic():
            choices = new_data.pop('choice_set', [])
            question = Question(**new_data)
            question.save()
            for choice in choices:
                question.choice_set.create(**choice)
            return question

    async def post(self, request, *args, **kwargs) -> JsonResponse:
        post = schemas.QuestionPost(**get_body(request))
        question = await self.atomic_operation(post)
        fetched_question = await Question.objects.prefetch_related('choice_set').aget(pk=question.pk)
        data = schemas.QuestionOut.model_validate(fetched_question)
        return JsonResponse(data.dict())


class AsyncPollsDetail(AsyncAPIView):
    authentication_classes = (authentication.BasicAuthentication,)
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)

    async def get(self, request, *args, **kwargs) -> JsonResponse:
        instance = await aget_object_or_404(Question.objects.prefetch_related('choice_set',), pk=kwargs['pk'])
        data = schemas.QuestionOut.model_validate(instance)
        return JsonResponse(data.model_dump())

    async def patch(self, request, *args, **kwargs) -> JsonResponse:
        instance = await aget_object_or_404(Question.objects.prefetch_related('choice_set',), pk=kwargs['pk'])
        current_data = schemas.QuestionUpdate.model_validate(instance)
        patch_data = schemas.QuestionUpdate(**get_body(request)).model_dump(exclude_unset=True)
        updated_data = current_data.model_copy(update=patch_data)
        for attr, value in updated_data.model_dump().items():
            setattr(instance, attr, value)
        await instance.asave()
        return JsonResponse(schemas.QuestionOut.model_validate(instance).model_dump())
