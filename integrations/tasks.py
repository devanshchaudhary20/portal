from celery import shared_task
from .models import ScheduledPost
from .views import post_on_linkedin_now, post_on_twitter
from django.utils import timezone


@shared_task
def process_scheduled_posts():
    current_time = timezone.now()
    scheduled_posts = ScheduledPost.objects.filter(status='scheduled', scheduled_at__lte=current_time)

    for post in scheduled_posts:
        try:
            if post.platform == 'linkedin':
                post_on_linkedin_now(post)
            elif post.platform == 'twitter':
                post_on_twitter(post.content)
            post.status = 'posted'
            post.save()
        except Exception as e:
            print(e)

