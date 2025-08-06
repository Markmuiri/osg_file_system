from django.urls import path
from . import views

app_name = 'file_manager_app'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),

    # User management
    path('register/', views.register_user, name='register'),
    path('profile/', views.profile_detail, name='profile_detail'),
    path('profile/edit/', views.profile_edit, name='profile_edit'),
    path('users/', views.user_list, name='user_list'),
    path('users/<int:pk>/', views.user_detail, name='user_detail'),
    path('users/<int:pk>/edit/', views.user_edit, name='user_edit'),
    path('users/<int:pk>/delete/confirm/', views.user_confirm_delete, name='user_confirm_delete'),

    # Incoming Letters
    path('letters/incoming/', views.incoming_letter_list, name='incoming_letter_list'),
    path('letters/incoming/add/', views.incoming_letter_form, name='incoming_letter_form'),
    path('letters/incoming/<int:pk>/', views.incoming_letter_detail, name='incoming_letter_detail'),
    path('letters/incoming/<int:pk>/edit/', views.incoming_letter_form, name='incoming_letter_edit'),
    path('letters/incoming/<int:pk>/delete/confirm/', views.incoming_letter_confirm_delete, name='incoming_letter_confirm_delete'),
    path('letters/incoming/<int:pk>/print-and-move/', views.incoming_letter_print_and_move, name='incoming_letter_print_and_move'),

    # Outgoing Letters
    path('letters/outgoing/', views.outgoing_letter_list, name='outgoing_letter_list'),
    path('letters/outgoing/add/', views.outgoing_letter_form, name='outgoing_letter_form'),
    path('letters/outgoing/<int:pk>/', views.outgoing_letter_detail, name='outgoing_letter_detail'),
    path('letters/outgoing/<int:pk>/edit/', views.outgoing_letter_form, name='outgoing_letter_edit'),
    path('letters/outgoing/<int:pk>/delete/confirm/', views.outgoing_letter_confirm_delete, name='outgoing_letter_confirm_delete'),
    path('letters/outgoing/<int:pk>/receipt/', views.outgoing_letter_receipt, name='outgoing_letter_receipt'),

    # Filings
    path('filings/', views.filing_list, name='filing_list'),
    path('filings/add/', views.filing_form, name='filing_form'),
    path('filings/<int:pk>/', views.filing_detail, name='filing_detail'),
    path('filings/<int:pk>/edit/', views.filing_form, name='filing_edit'),
    path('filings/<int:pk>/delete/confirm/', views.filing_confirm_delete, name='filing_confirm_delete'),

    # Filing Documents
    path('filings/<int:filing_pk>/documents/add/', views.filing_document_form, name='filing_document_form'),
    path('filing-documents/<int:pk>/delete/confirm/', views.filing_document_confirm_delete, name='filing_document_confirm_delete'),

    # Search & Reports
    path('search/', views.search_results, name='search_results'),
    path('reports/', views.report_dashboard, name='report_dashboard'),
    path('reports/letter-volume/', views.letter_volume_report, name='letter_volume_report'),
    path('reports/filing-type/', views.filing_type_report, name='filing_type_report'),
]
