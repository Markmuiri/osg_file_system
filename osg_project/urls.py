# osg_project/urls.py

from django.contrib import admin
from django.urls import path, include, reverse_lazy
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from osg_project import views

# The root path now correctly redirects to the login view using the app's namespace
urlpatterns = [
    path('', views.index, name='index'),
    path('admin/', admin.site.urls),
    # This URL for the file manager app now includes the login and dashboard views
    path('file-manager/', include('osg_project.file_manager_app.urls', namespace='file_manager_app')),
    path('payments/', include('osg_project.payments_app.urls')),
    path('', views.index, name='index'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
