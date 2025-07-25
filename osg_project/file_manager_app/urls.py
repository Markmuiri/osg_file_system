from django.urls import path
from django.contrib.auth import views as auth_views # Import Django's built-in auth views
from . import views

urlpatterns = [
    # --- Authentication URLs ---
    # Using Django's built-in LoginView and LogoutView
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'), # Redirects to login after logout
    path('register/', views.register_user, name='register'), # Custom registration view

    # --- Dashboard URL ---
    path('dashboard/', views.dashboard, name='dashboard'),

    # --- User Management URLs ---
    path('profile/', views.profile_detail, name='profile_detail'),
    path('profile/edit/', views.profile_edit, name='profile_edit'),
    path('users/', views.user_list, name='user_list'),
    path('users/<int:pk>/', views.user_detail, name='user_detail'),
    path('users/<int:pk>/edit/', views.user_edit, name='user_edit'),
    path('users/<int:pk>/delete/confirm/', views.user_confirm_delete, name='user_confirm_delete'),

    # --- Incoming Letters URLs ---
    path('incoming-letters/', views.incoming_letter_list, name='incoming_letter_list'),
    path('incoming-letters/add/', views.incoming_letter_form, name='incoming_letter_form'),
    path('incoming-letters/<int:pk>/', views.incoming_letter_detail, name='incoming_letter_detail'),
    path('incoming-letters/<int:pk>/edit/', views.incoming_letter_form, name='incoming_letter_edit'),
    path('incoming-letters/<int:pk>/delete/confirm/', views.incoming_letter_confirm_delete, name='incoming_letter_confirm_delete'),

    # --- Outgoing Letters URLs ---
    path('outgoing-letters/', views.outgoing_letter_list, name='outgoing_letter_list'),
    path('outgoing-letters/add/', views.outgoing_letter_form, name='outgoing_letter_form'),
    path('outgoing-letters/<int:pk>/', views.outgoing_letter_detail, name='outgoing_letter_detail'),
    path('outgoing-letters/<int:pk>/edit/', views.outgoing_letter_form, name='outgoing_letter_edit'),
    path('outgoing-letters/<int:pk>/delete/confirm/', views.outgoing_letter_confirm_delete, name='outgoing_letter_confirm_delete'),
    path('outgoing-letters/<int:pk>/receipt/', views.outgoing_letter_receipt, name='outgoing_letter_receipt'), # For printing receipt

    # --- Filings URLs ---
    path('filings/', views.filing_list, name='filing_list'),
    path('filings/add/', views.filing_form, name='filing_form'),
    path('filings/<int:pk>/', views.filing_detail, name='filing_detail'),
    path('filings/<int:pk>/edit/', views.filing_form, name='filing_edit'),
    path('filings/<int:pk>/delete/confirm/', views.filing_confirm_delete, name='filing_confirm_delete'),

    # --- Filing Documents URLs ---
    path('filings/<int:filing_pk>/documents/add/', views.filing_document_form, name='filing_document_form'),
    path('filing-documents/<int:pk>/delete/confirm/', views.filing_document_confirm_delete, name='filing_document_confirm_delete'),

    # --- Search & Reporting URLs ---
    path('search/', views.search_results, name='search_results'),
    path('reports/', views.report_dashboard, name='report_dashboard'),
    path('reports/letter-volume/', views.letter_volume_report, name='letter_volume_report'),
    path('reports/filing-type/', views.filing_type_report, name='filing_type_report'),
]
