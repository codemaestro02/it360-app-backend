from django.contrib import admin
from .models import User

# Register your models here.
admin.site.site_header = "IT360 Admin"
admin.site.site_title = "IT360 Admin Portal"
admin.site.index_title = "Welcome to the IT360 Admin Portal"

admin.site.register(User)
