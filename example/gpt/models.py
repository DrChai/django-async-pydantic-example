from django.db import models
from django.utils import timezone, text
# Create your models here.


class Completion(models.Model):
    prompt = models.TextField(max_length=5000)
    created = models.DateTimeField("date created", default=timezone.now)
    completion = models.TextField(max_length=5000)
    model = models.CharField()

    def __str__(self):
        return text.Truncator(self.message).chars(30)
