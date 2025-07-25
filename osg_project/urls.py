# osg_project/urls.py

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

# Import custom error views
from file_manager_app import views as file_manager_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('file_manager_app.urls')), # Include your file_manager_app URLs at the root
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Custom error handlers (optional, but good practice)
handler403 = file_manager_views.custom_403_view
handler404 = file_manager_views.custom_404_view
handler500 = file_manager_views.custom_500_view
