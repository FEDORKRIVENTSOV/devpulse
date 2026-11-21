from django.contrib import admin
from .models import Monitor, CheckResult

admin.site.register(Monitor)
admin.site.register(CheckResult)

# Register your models here.
