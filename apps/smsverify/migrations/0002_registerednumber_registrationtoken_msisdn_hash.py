from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('smsverify', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='registrationtoken',
            name='msisdn_hash',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.CreateModel(
            name='RegisteredNumber',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('msisdn_hash', models.CharField(db_index=True, max_length=64, unique=True)),
                ('registered_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
