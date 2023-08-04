# django-async-pydantic-example
Django Example of integration with Pydantic and Async framework

## Background
When building a RESTful API on Django, [Django REST framework](https://www.django-rest-framework.org/) is probably the first framework that comes to mind. It provides all the necessary functions for production. After using DRF for years, it became evident that the performance of core functionality - data validation had limitations. Considering to get benefits of [Pydantic V2](https://docs.pydantic.dev/latest/)(validation logic implemented in Rust) and asyncio, a few scripts in [django_router]() and related [example]() may help.

### 😌 Mitigation Approach
Rewrite DRF's `APIView` to make it [asynchronous](https://github.com/DrChai/django-async-pydantic-example/blob/main/django_router/views.py#L13), and use Pydantic as your data serialization and validation:
```python
#schemas.py
class QuestionPost(BaseModel):
    # Pydantic V2:
    model_config = ConfigDict(from_attributes=True)
    pub_date: datetime | None = Field(default_factory=timezone.now)
    question_text: constr(max_length=200)
    choice_set: list[ChoicePost]
    # Pydantic V1:
    # class Config:
        # orm_mode = True
        # getter_dict = ModelGetterDict


class QuestionOut(QuestionPost):
    id: int

#views.py
class AsyncPollsDetail(AsyncAPIView):
    authentication_classes = (authentication.BasicAuthentication,)
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)

    async def get(self, request, *args, **kwargs) -> JsonResponse:
        instance = await aget_object_or_404(Question.objects.prefetch_related('choice_set',), pk=kwargs['pk'])
        data = schemas.QuestionOut.from_orm(instance)
        return JsonResponse(data.dict())
    #...
```
More examples in [polls](https://github.com/DrChai/django-async-pydantic-example/blob/main/example/polls/views.py)(same application in Django official tutorial) 
### 🌶️ Spicy Approach
To take the step further and make the whole interface in `FastAPI` manner. A decorator [`Router`](https://github.com/DrChai/django-async-pydantic-example/blob/main/django_router/routing.py#L286) is provided and a real-world example can be found in the [gpt](https://github.com/DrChai/django-async-pydantic-example/blob/main/example/gpt/views.py) application. `def completion()` returns the response to the client immediately once the awaitable `openai.Completion.acreate()` which interacts with the ChatGPT endpoint yields a result. It then arranges with `asyncio.Task` in a separate thread to handle IO jobs, such as saving the record to the database. 
```python
#views.py
gpt_router = Router(authentication_classes=[authentication.BasicAuthentication, ])

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
# urls.py
urlpatterns = [
    path('admin/', admin.site.urls),
    path("polls/", include("polls.urls")),
]
urlpatterns += gpt_router.get_urls()
```