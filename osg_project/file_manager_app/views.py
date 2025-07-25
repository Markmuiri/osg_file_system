# file_manager_app/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.db.models import Count, Q # Q for complex lookups in search/reports
from django.utils import timezone
from django.conf import settings # To access MEDIA_ROOT for file handling
import os # For file path manipulation
from django.core.files.storage import FileSystemStorage # For manual file saving

# Import your models
from .models import (
    Profile, IncomingLetter, OutgoingLetter,
    Filing, FilingDocument
)

# --- Helper for Superuser Check ---
def is_superuser(user):
    return user.is_superuser

# --- Authentication Views (using Django's built-in views in urls.py is common) ---
# For login/logout, Django provides built-in views in django.contrib.auth.views.
# You'll typically configure these in your osg_project/urls.py or file_manager_app/urls.py
# Example:
# from django.contrib.auth import views as auth_views
# path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
# path('logout/', auth_views.LogoutView.as_view(next_page='/login/'), name='logout'),

# --- Dashboard View ---
@login_required
def dashboard(request):
    """
    Renders the main dashboard with quick access cards and key statistics.
    """
    # Quick Access Card Data (placeholders)
    total_incoming = IncomingLetter.objects.count()
    total_outgoing = OutgoingLetter.objects.count()
    total_filings = Filing.objects.count()
    recent_incoming = IncomingLetter.objects.order_by('-received_date')[:5]
    recent_filings = Filing.objects.order_by('-receiving_date')[:5]

    context = {
        'total_incoming': total_incoming,
        'total_outgoing': total_outgoing,
        'total_filings': total_filings,
        'recent_incoming': recent_incoming,
        'recent_filings': recent_filings,
    }
    return render(request, 'dashboard.html', context)

# --- User Management Views ---
def register_user(request):
    """
    Handles user registration.
    """
    if request.method == 'POST':
        # In a real app, use Django's UserCreationForm or a custom form
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        employee_number = request.POST.get('employee_number')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')

        if password != password_confirm:
            # Handle password mismatch error
            return render(request, 'users/register.html', {'error': 'Passwords do not match.'})

        try:
            user = User.objects.create_user(username=username, email=email, password=password,
                                            first_name=first_name, last_name=last_name)
            # Profile is created automatically by signal, just update employee_number and picture
            profile = user.profile
            profile.employee_number = employee_number
            if 'profile_picture' in request.FILES:
                profile.profile_picture = request.FILES['profile_picture']
            profile.save()

            # Optionally log the user in after registration
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard') # Redirect to dashboard after successful registration
            else:
                return render(request, 'users/register.html', {'error': 'Authentication failed after registration.'})

        except Exception as e:
            # Handle unique constraint errors or other validation errors
            return render(request, 'users/register.html', {'error': f'Registration failed: {e}'})
    return render(request, 'users/register.html')

@login_required
def profile_detail(request):
    """
    Displays the logged-in user's profile information.
    """
    # The profile is accessed via request.user.profile due to OneToOneField
    return render(request, 'users/profile_detail.html', {'user_profile': request.user.profile})

@login_required
def profile_edit(request):
    """
    Handles updating the logged-in user's profile.
    """
    user = request.user
    profile = user.profile

    if request.method == 'POST':
        # In a real app, use Django Forms for User and Profile
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.email = request.POST.get('email', user.email)
        user.save()

        profile.employee_number = request.POST.get('employee_number', profile.employee_number)
        if 'profile_picture' in request.FILES:
            profile.profile_picture = request.FILES['profile_picture']
        profile.save()

        return redirect('profile_detail')
    
    context = {'user_profile': profile, 'user': user}
    return render(request, 'users/profile_edit.html', context)

@login_required
@user_passes_test(is_superuser) # Only superusers can access this
def user_list(request):
    """
    (Superuser only) Displays a list of all users and their profiles.
    """
    users = User.objects.all().select_related('profile').order_by('username')
    context = {'users': users}
    return render(request, 'users/user_list.html', context)

@login_required
@user_passes_test(is_superuser) # Only superusers can access this
def user_detail(request, pk):
    """
    (Superuser only) Shows detailed information for a specific user.
    """
    user = get_object_or_404(User.objects.select_related('profile'), pk=pk)
    context = {'user_obj': user} # Renamed to avoid conflict with 'user' in base template
    return render(request, 'users/user_detail.html', context)

@login_required
@user_passes_test(is_superuser) # Only superusers can access this
def user_edit(request, pk):
    """
    (Superuser only) Handles editing other user profiles.
    """
    user = get_object_or_404(User.objects.select_related('profile'), pk=pk)
    profile = user.profile

    if request.method == 'POST':
        # In a real app, use Django Forms for User and Profile
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.email = request.POST.get('email', user.email)
        # Superuser can also change role
        profile.role = request.POST.get('role', profile.role)
        user.save()
        profile.employee_number = request.POST.get('employee_number', profile.employee_number)
        if 'profile_picture' in request.FILES:
            profile.profile_picture = request.FILES['profile_picture']
        profile.save()
        return redirect('user_detail', pk=user.pk)
    
    context = {'user_obj': user, 'user_profile': profile, 'roles': Profile.ROLE_CHOICES}
    return render(request, 'users/user_edit.html', context)

@login_required
@user_passes_test(is_superuser) # Only superusers can access this
def user_confirm_delete(request, pk):
    """
    (Superuser only) Confirms before deleting a user.
    """
    user_to_delete = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        user_to_delete.delete()
        return redirect('user_list')
    context = {'user_obj': user_to_delete}
    return render(request, 'users/user_confirm_delete.html', context)


# --- Incoming Letters Views ---
@login_required
def incoming_letter_list(request):
    """Displays a list of all incoming letters."""
    letters = IncomingLetter.objects.all().select_related('receiving_officer', 'signed_by')
    context = {'incoming_letters': letters}
    return render(request, 'incoming_letters/incoming_letter_list.html', context)

@login_required
def incoming_letter_detail(request, pk):
    """Shows detailed information for a specific incoming letter."""
    letter = get_object_or_404(IncomingLetter.objects.select_related('receiving_officer', 'signed_by'), pk=pk)
    context = {'incoming_letter': letter}
    return render(request, 'incoming_letters/incoming_letter_detail.html', context)

@login_required
def incoming_letter_form(request, pk=None):
    """
    Handles adding new incoming letters and editing existing ones.
    Includes permission logic for 'receiving_officer'.
    """
    incoming_letter = None
    if pk:
        incoming_letter = get_object_or_404(IncomingLetter, pk=pk)

    # Permission logic for receiving_officer field
    if request.user.is_superuser:
        # Superuser can select any user
        receiving_officers = User.objects.all().order_by('username')
    else:
        # Non-superuser can only select themselves
        receiving_officers = User.objects.filter(pk=request.user.pk)

    if request.method == 'POST':
        # In a real app, use Django Forms with crispy forms or custom widgets
        data = request.POST.copy() # Make a mutable copy
        
        # If not superuser, force receiving_officer to current user
        if not request.user.is_superuser:
            data['receiving_officer'] = request.user.pk

        if incoming_letter: # Editing existing
            incoming_letter.received_date = data.get('received_date', incoming_letter.received_date)
            incoming_letter.serial_number = data.get('serial_number', incoming_letter.serial_number)
            incoming_letter.date_of_letter = data.get('date_of_letter', incoming_letter.date_of_letter)
            incoming_letter.reference = data.get('reference', incoming_letter.reference)
            incoming_letter.subject = data.get('subject', incoming_letter.subject)
            incoming_letter.author = data.get('author', incoming_letter.author)
            incoming_letter.receiving_officer = get_object_or_404(User, pk=data['receiving_officer'])
            incoming_letter.remarks = data.get('remarks', incoming_letter.remarks)
            incoming_letter.signed_by = get_object_or_404(User, pk=data['signed_by']) if data.get('signed_by') else None
            incoming_letter.signed_at = data.get('signed_at', incoming_letter.signed_at)
            incoming_letter.sender = data.get('sender', incoming_letter.sender)
            incoming_letter.is_actioned = data.get('is_actioned') == 'on' # Checkbox value 'on'

            if 'scanned_copy' in request.FILES:
                incoming_letter.scanned_copy = request.FILES['scanned_copy']
            incoming_letter.save()
        else: # Creating new
            IncomingLetter.objects.create(
                received_date=data['received_date'],
                serial_number=data['serial_number'],
                date_of_letter=data['date_of_letter'],
                reference=data['reference'],
                subject=data['subject'],
                author=data['author'],
                receiving_officer=get_object_or_404(User, pk=data['receiving_officer']),
                remarks=data.get('remarks'),
                scanned_copy=request.FILES.get('scanned_copy'),
                signed_by=get_object_or_404(User, pk=data['signed_by']) if data.get('signed_by') else None,
                signed_at=data.get('signed_at'),
                sender=data.get('sender'),
                is_actioned=data.get('is_actioned') == 'on',
            )
        return redirect('incoming_letter_list')
    else:
        context = {
            'incoming_letter': incoming_letter,
            'receiving_officers': receiving_officers,
            'all_users': User.objects.all().order_by('username'), # For signed_by dropdown
        }
        return render(request, 'incoming_letters/incoming_letter_form.html', context)

@login_required
def incoming_letter_confirm_delete(request, pk):
    """Confirms before deleting an incoming letter record."""
    incoming_letter = get_object_or_404(IncomingLetter, pk=pk)
    if request.method == 'POST':
        incoming_letter.delete()
        return redirect('incoming_letter_list')
    context = {'incoming_letter': incoming_letter}
    return render(request, 'incoming_letters/incoming_letter_confirm_delete.html', context)


# --- Outgoing Letters Views ---
@login_required
def outgoing_letter_list(request):
    """Displays a list of all outgoing letters."""
    letters = OutgoingLetter.objects.all().select_related('sent_by')
    context = {'outgoing_letters': letters}
    return render(request, 'outgoing_letters/outgoing_letter_list.html', context)

@login_required
def outgoing_letter_detail(request, pk):
    """Shows detailed information for a specific outgoing letter."""
    letter = get_object_or_404(OutgoingLetter.objects.select_related('sent_by'), pk=pk)
    context = {'outgoing_letter': letter}
    return render(request, 'outgoing_letters/outgoing_letter_detail.html', context)

@login_required
def outgoing_letter_form(request, pk=None):
    """
    Handles adding new outgoing letters and editing existing ones.
    """
    outgoing_letter = None
    if pk:
        outgoing_letter = get_object_or_404(OutgoingLetter, pk=pk)

    # For 'sent_by' field, allow all users to be selected
    all_users = User.objects.all().order_by('username')

    if request.method == 'POST':
        # In a real app, use Django Forms
        sent_by_user = get_object_or_404(User, pk=request.POST['sent_by']) if request.POST.get('sent_by') else None

        if outgoing_letter: # Editing existing
            outgoing_letter.date_sent = request.POST.get('date_sent', outgoing_letter.date_sent)
            outgoing_letter.serial_number = request.POST.get('serial_number', outgoing_letter.serial_number)
            outgoing_letter.reference = request.POST.get('reference', outgoing_letter.reference)
            outgoing_letter.subject = request.POST.get('subject', outgoing_letter.subject)
            outgoing_letter.recipient = request.POST.get('recipient', outgoing_letter.recipient)
            outgoing_letter.sent_by = sent_by_user
            outgoing_letter.remarks = request.POST.get('remarks', outgoing_letter.remarks)
            if 'scanned_copy' in request.FILES:
                outgoing_letter.scanned_copy = request.FILES['scanned_copy']
            outgoing_letter.save()
        else: # Creating new
            OutgoingLetter.objects.create(
                date_sent=request.POST['date_sent'],
                serial_number=request.POST['serial_number'],
                reference=request.POST['reference'],
                subject=request.POST['subject'],
                recipient=request.POST['recipient'],
                sent_by=sent_by_user,
                remarks=request.POST.get('remarks'),
                scanned_copy=request.FILES.get('scanned_copy'),
            )
        return redirect('outgoing_letter_list')
    else:
        context = {
            'outgoing_letter': outgoing_letter,
            'all_users': all_users,
        }
        return render(request, 'outgoing_letters/outgoing_letter_form.html', context)

@login_required
def outgoing_letter_confirm_delete(request, pk):
    """Confirms before deleting an outgoing letter record."""
    outgoing_letter = get_object_or_404(OutgoingLetter, pk=pk)
    if request.method == 'POST':
        outgoing_letter.delete()
        return redirect('outgoing_letter_list')
    context = {'outgoing_letter': outgoing_letter}
    return render(request, 'outgoing_letters/outgoing_letter_confirm_delete.html', context)

@login_required
def outgoing_letter_receipt(request, pk):
    """Generates and displays a printable receipt for an outgoing letter."""
    outgoing_letter = get_object_or_404(OutgoingLetter.objects.select_related('sent_by'), pk=pk)
    context = {'outgoing_letter': outgoing_letter}
    return render(request, 'outgoing_letters/outgoing_letter_receipt.html', context)


# --- Filings Views ---
@login_required
def filing_list(request):
    """Displays a list of all filings."""
    filings = Filing.objects.all().select_related('receiving_officer')
    context = {'filings': filings}
    return render(request, 'filings/filing_list.html', context)

@login_required
def filing_detail(request, pk):
    """Shows detailed information for a specific filing, including its documents."""
    filing = get_object_or_404(Filing.objects.select_related('receiving_officer'), pk=pk)
    filing_documents = filing.documents.all() # Accessing related documents
    context = {
        'filing': filing,
        'filing_documents': filing_documents,
    }
    return render(request, 'filings/filing_detail.html', context)

@login_required
def filing_form(request, pk=None):
    """
    Handles adding new filings and editing existing ones.
    Includes permission logic for 'officer' (receiving_officer).
    """
    filing = None
    if pk:
        filing = get_object_or_404(Filing, pk=pk)

    # Permission logic for receiving_officer field
    if request.user.is_superuser:
        # Superuser can select any user
        receiving_officers = User.objects.all().order_by('username')
    else:
        # Non-superuser can only select themselves
        receiving_officers = User.objects.filter(pk=request.user.pk)

    if request.method == 'POST':
        # In a real app, use Django Forms
        data = request.POST.copy() # Make a mutable copy
        
        # If not superuser, force receiving_officer to current user
        if not request.user.is_superuser:
            data['receiving_officer'] = request.user.pk

        receiving_officer_obj = get_object_or_404(User, pk=data['receiving_officer'])

        if filing: # Editing existing
            filing.file_reference = data.get('file_reference', filing.file_reference)
            filing.file_name = data.get('file_name', filing.file_name)
            filing.serial_number = data.get('serial_number', filing.serial_number)
            filing.receiving_department = data.get('receiving_department', filing.receiving_department)
            filing.receiving_officer = receiving_officer_obj
            filing.receiving_date = data.get('receiving_date', filing.receiving_date)
            if 'scanned_copy' in request.FILES:
                filing.scanned_copy = request.FILES['scanned_copy']
            filing.save()
        else: # Creating new
            Filing.objects.create(
                file_reference=data['file_reference'],
                file_name=data['file_name'],
                serial_number=data['serial_number'],
                receiving_department=data['receiving_department'],
                receiving_officer=receiving_officer_obj,
                receiving_date=data['receiving_date'],
                scanned_copy=request.FILES.get('scanned_copy'),
            )
        return redirect('filing_list')
    else:
        context = {
            'filing': filing,
            'receiving_officers': receiving_officers,
        }
        return render(request, 'filings/filing_form.html', context)

@login_required
def filing_confirm_delete(request, pk):
    """Confirms before deleting a filing record."""
    filing = get_object_or_404(Filing, pk=pk)
    if request.method == 'POST':
        filing.delete()
        return redirect('filing_list')
    context = {'filing': filing}
    return render(request, 'filings/filing_confirm_delete.html', context)

@login_required
def filing_document_form(request, filing_pk):
    """
    Handles uploading new documents to an existing filing.
    Includes file validation for CSV/Excel.
    """
    filing = get_object_or_404(Filing, pk=filing_pk)

    if request.method == 'POST':
        document_name = request.POST.get('document_name')
        folio_number = request.POST.get('folio_number')
        uploaded_file = request.FILES.get('uploaded_file')

        if not uploaded_file:
            return render(request, 'filings/filing_document_form.html', {
                'filing': filing, 'error': 'No file uploaded.'
            })

        try:
            # The validator is attached to the model field, so it runs on save
            filing_document = FilingDocument(
                filing=filing,
                document_name=document_name,
                folio_number=folio_number,
                uploaded_file=uploaded_file
            )
            filing_document.full_clean() # Run model's validators
            filing_document.save()
            return redirect('filing_detail', pk=filing.pk)
        except ValidationError as e:
            return render(request, 'filings/filing_document_form.html', {
                'filing': filing, 'error': e.message
            })
        except Exception as e:
            return render(request, 'filings/filing_document_form.html', {
                'filing': filing, 'error': f'File upload failed: {e}'
            })

    context = {'filing': filing}
    return render(request, 'filings/filing_document_form.html', context)

@login_required
def filing_document_confirm_delete(request, pk):
    """Confirms before deleting a filing document."""
    filing_document = get_object_or_404(FilingDocument, pk=pk)
    filing_pk = filing_document.filing.pk # Get parent filing's PK for redirect
    if request.method == 'POST':
        filing_document.delete()
        return redirect('filing_detail', pk=filing_pk)
    context = {'filing_document': filing_document}
    return render(request, 'filings/filing_document_confirm_delete.html', context)


# --- Search & Reporting Views ---
@login_required
def search_results(request):
    """
    Handles general search across letters and filings.
    """
    query = request.GET.get('q', '')
    incoming_results = []
    outgoing_results = []
    filing_results = []

    if query:
        incoming_results = IncomingLetter.objects.filter(
            Q(subject__icontains=query) |
            Q(reference__icontains=query) |
            Q(author__icontains=query) |
            Q(receiving_officer__username__icontains=query)
        ).distinct()

        outgoing_results = OutgoingLetter.objects.filter(
            Q(subject__icontains=query) |
            Q(reference__icontains=query) |
            Q(recipient__icontains=query) |
            Q(sent_by__username__icontains=query)
        ).distinct()

        filing_results = Filing.objects.filter(
            Q(file_name__icontains=query) |
            Q(file_reference__icontains=query) |
            Q(serial_number__icontains=query) |
            Q(receiving_department__icontains=query) |
            Q(receiving_officer__username__icontains=query)
        ).distinct()

    context = {
        'query': query,
        'incoming_results': incoming_results,
        'outgoing_results': outgoing_results,
        'filing_results': filing_results,
    }
    return render(request, 'search/search_results.html', context)

@login_required
def report_dashboard(request):
    """Displays an overview of available reports."""
    return render(request, 'reports/report_dashboard.html')

@login_required
def letter_volume_report(request):
    """Generates and displays a report on letter volumes."""
    # Example: Count incoming/outgoing letters by month/year
    incoming_counts = IncomingLetter.objects.extra({'month': "strftime('%%Y-%%m', received_date)"}).values('month').annotate(count=Count('id')).order_by('month')
    outgoing_counts = OutgoingLetter.objects.extra({'month': "strftime('%%Y-%%m', date_sent)"}).values('month').annotate(count=Count('id')).order_by('month')

    context = {
        'incoming_counts': incoming_counts,
        'outgoing_counts': outgoing_counts,
    }
    return render(request, 'reports/letter_volume_report.html', context)

@login_required
def filing_type_report(request):
    """Generates and displays a report on filing types (e.g., by department)."""
    filing_department_counts = Filing.objects.values('receiving_department').annotate(count=Count('id')).order_by('receiving_department')
    
    context = {
        'filing_department_counts': filing_department_counts,
    }
    return render(request, 'reports/filing_type_report.html', context)


# --- Custom Error Views (Optional, but good practice for Django) ---
# These would be configured in your main urls.py with handler403, handler404, handler500
def custom_403_view(request, exception):
    return render(request, '403.html', status=403)

def custom_404_view(request, exception):
    return render(request, '404.html', status=404)

def custom_500_view(request):
    return render(request, '500.html', status=500)

