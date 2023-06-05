import asyncio
import os
from typing import Literal
import openai
from django.http import HttpRequest
from pydantic import BaseModel, conint, constr
import redis.asyncio as redis
from django_router import Router
from django_router.rest_framework import authentication, permissions

openai.api_key = os.environ.get('OPENAI_APIKEY')

# Create your views here.
gpt_router = Router(authentication_classes=[authentication.BasicAuthentication, ])
ModelID = Literal['ada', 'curie', 'davinci']


class CompletionRequest(BaseModel):
    prompt: constr(max_length=200)
    max_tokens: conint(le=2049, ge=16) = 16
    n: conint(le=3, ge=1) = 1
    model: ModelID = 'ada'


async def save_to_db(view_rts, **view_kwargs):
    await asyncio.sleep(3)
    print(f'save_to_db with params: ret: {view_rts}, kwargs: {view_kwargs}')


async def update_stat(view_rts, **view_kwargs):
    connection = redis.Redis(password=os.environ.get('REDIS_PWD'))
    user = view_kwargs.get('request').user
    total_tokens = view_rts.get('usage', {}).get('total_tokens', None)
    async with connection.pipeline(transaction=True) as pipe:
        await (pipe.hincrby(f'{user.username}:stats', "tokens", total_tokens).
               hincrby(f'{user.username}:stats', "req", 1).execute())


@gpt_router.post(
    r'completion$',
    permissions=[permissions.IsAuthenticated, ],
    async_tasks=[update_stat, save_to_db])
async def completion(body: CompletionRequest, request: HttpRequest):
    patch_data = body.dict()
    patch_data |= {'user': request.user.username}
    completion_resp = await openai.Completion.acreate(**patch_data)
    return completion_resp


@gpt_router.get('completion/stats', permissions=[permissions.IsAuthenticated,])
async def stats(request: HttpRequest):
    connection = redis.Redis(password=os.environ.get('REDIS_PWD'), decode_responses=True)
    user = request.user
    stats = await connection.hgetall(f'{user.username}:stats')
    return stats or {'detail': 'Not found'}
