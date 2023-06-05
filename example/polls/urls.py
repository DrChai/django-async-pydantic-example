from django.urls import path

from . import views

urlpatterns = [
    path("", views.AsyncPollsList.as_view(), name="post-list"),
    path("<int:pk>", views.AsyncPollsDetail.as_view(), name="get-patch-detail"),
]
