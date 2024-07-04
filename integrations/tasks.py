from celery import shared_task
from .models import ScheduledPost
from .views import post_on_linkedin_now, post_on_twitter_now
from django.utils import timezone
import pytz


@shared_task
def process_scheduled_posts():
    utc_now = timezone.now()
    current_time = timezone.localtime(utc_now, pytz.timezone('Asia/Kolkata'))
    scheduled_posts = ScheduledPost.objects.filter(status='scheduled', scheduled_at__lte=current_time)

    for post in scheduled_posts:
        try:
            if post.platform == 'linkedin':
                post_on_linkedin_now(post)
                print(post)
            elif post.platform == 'twitter':
                post_on_twitter_now(post)
            post.status = 'posted'
            post.save()
        except Exception as e:
            print(e)

