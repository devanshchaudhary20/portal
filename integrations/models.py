from django.db import models

class ScheduledPost(models.Model):
    content = models.TextField()
    scheduled_at = models.DateTimeField()
    platform = models.CharField(max_length=20)  # 'linkedin' or 'twitter'
    status = models.CharField(max_length=20, default='scheduled')  # 'scheduled', 'posted', 'failed'
    access_token = models.CharField(max_length=500, default=None)
