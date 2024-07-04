from django.db import models

class Firm(models.Model):
    name = models.CharField(max_length=255)
    geographic_area = models.CharField(max_length=255)
    ceo = models.CharField(max_length=255)
    linkedin_handle = models.CharField(max_length=255)
    twitter_handle = models.CharField(max_length=255)

    def __str__(self):
        return self.name
