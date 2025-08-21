# osg_project/file_manager_app/urls.py

from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

app_name = 'file_manager_app'

urlpatterns = [
    # --- User Authentication and Management ---
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.UserRegisterView.as_view(), name='register'),
    path('profile/', views.ProfileDetailView.as_view(), name='profile_detail'),
    path('profile/edit/', views.ProfileEditView.as_view(), name='profile_edit'),
    path('users/', views.UserListView.as_view(), name='user_list'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user_detail'),
    path('users/<int:pk>/edit/', views.UserEditView.as_view(), name='user_edit'),
    path('users/<int:pk>/delete/confirm/', views.UserDeleteView.as_view(), name='user_confirm_delete'),

    # API endpoints for JWT authentication
    path('token/obtain/', views.ObtainTokenView.as_view(), name='token-obtain'),
    path('token/refresh/', views.RefreshTokenView.as_view(), name='token-refresh'),

    # Dashboard
    path('', views.dashboard, name='dashboard'),

    # Incoming Letters (function-based views)
    path('letters/incoming/', views.incoming_letter_list, name='incoming_letter_list'),
    path('letters/incoming/add/', views.incoming_letter_form, name='incoming_letter_form'),
    path('letters/incoming/<int:pk>/', views.incoming_letter_detail, name='incoming_letter_detail'),
    path('letters/incoming/<int:pk>/edit/', views.incoming_letter_form, name='incoming_letter_edit'),
    path('letters/incoming/<int:pk>/delete/confirm/', views.incoming_letter_confirm_delete, name='incoming_letter_confirm_delete'),
    path('letters/incoming/<int:pk>/print-and-move/', views.incoming_letter_print_and_move, name='incoming_letter_print_and_move'),

    # Outgoing Letters (function-based views)
    path('letters/outgoing/', views.outgoing_letter_list, name='outgoing_letter_list'),
    path('letters/outgoing/add/', views.outgoing_letter_form, name='outgoing_letter_form'),
    path('letters/outgoing/<int:pk>/', views.outgoing_letter_detail, name='outgoing_letter_detail'),
    path('letters/outgoing/<int:pk>/edit/', views.outgoing_letter_form, name='outgoing_letter_edit'),
    path('letters/outgoing/<int:pk>/delete/confirm/', views.outgoing_letter_confirm_delete, name='outgoing_letter_confirm_delete'),
    path('letters/outgoing/<int:pk>/receipt/', views.outgoing_letter_receipt, name='outgoing_letter_receipt'),

    # Filings (function-based views)
    path('filings/', views.filing_list, name='filing_list'),
    path('filings/add/', views.filing_form, name='filing_form'),
    path('filings/<int:pk>/', views.filing_detail, name='filing_detail'),
    path('filings/<int:pk>/edit/', views.filing_form, name='filing_edit'),
    path('filings/<int:pk>/delete/confirm/', views.filing_confirm_delete, name='filing_confirm_delete'),

    # Filing Documents (function-based and class-based views)
    path('filings/<int:filing_pk>/documents/add/', views.filing_document_form, name='filing_document_form'),
    path('filing-documents/<int:pk>/delete/confirm/', views.FilingDocumentDeleteView.as_view(), name='filing_document_confirm_delete'),

    # Search & Reports (function-based views)
    path('search/', views.search_results, name='search_results'),
    path('reports/', views.report_dashboard, name='report_dashboard'),
    path('reports/letter-volume/', views.letter_volume_report, name='letter_volume_report'),
    path('reports/filing-type/', views.filing_type_report, name='filing_type_report'),

    # Archived Files (function-based views)
    path('files/archived/', views.archived_files_list, name='archived_files_list'),
    path('files/archived/<int:pk>/restore/', views.restore_archived_file, name='restore_archived_file'),
]
