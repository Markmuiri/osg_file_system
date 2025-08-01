# osg_project/urls.py

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from osg_project.file_manager_app import views as file_manager_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('django.contrib.auth.urls')),  # Django auth (login/logout/password)
    path('register/', file_manager_views.register_user, name='register'),
    path('', include(('osg_project.file_manager_app.urls', 'file_manager_app'), namespace='file_manager_app')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

handler403 = file_manager_views.custom_403_view
handler404 = file_manager_views.custom_404_view
handler500 = file_manager_views.custom_500_view
