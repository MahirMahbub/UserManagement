# Generated by Django 4.2.7 on 2023-11-23 04:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_portal', '0005_admin_created_at_admin_updated_at_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='admin',
            name='phone_number',
            field=models.CharField(max_length=10),
        ),
    ]
