# Generated by Django 5.0.6 on 2024-07-01 02:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0002_scheduledpost_access_token'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scheduledpost',
            name='access_token',
            field=models.CharField(default=None, max_length=500),
        ),
    ]