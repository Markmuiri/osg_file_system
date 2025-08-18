# osg_project/views.py

from django.shortcuts import render
from django.contrib.auth.decorators import login_required


def index(request):
    """
    Renders the main landing page of the project.
    
    This view serves as the central hub for navigating to different
    applications within the project.
    """
    return render(request, 'index.html')

