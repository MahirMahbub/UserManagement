# Generated by Django 4.2.7 on 2023-11-05 13:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user_portal', '0002_alter_saltedpasswordmodel_hashed_special_key'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='saltedpasswordmodel',
            name='salt',
        ),
    ]
