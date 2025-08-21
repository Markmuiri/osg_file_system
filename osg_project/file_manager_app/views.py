# file_manager_app/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.template.loader import render_to_string
import tempfile
from django.contrib import messages

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
import requests
import json
import jwt

# Import forms and models from the local app
from .forms import (
    CustomUserCreationForm,
    CustomUserChangeForm,
    IncomingLetterForm,
    OutgoingLetterForm,
    FilingForm,
    FilingDocumentForm,
)
from .file_utils import delete_file_soft, setup_directories, restore_file
from .models import IncomingLetter, OutgoingLetter, Filing, FilingDocument, ArchivedFile, Profile

# Use the custom user model throughout the application
User = get_user_model()


# --- Custom Mixins and Helper Functions ---
class SuperuserRequiredMixin(AccessMixin):
    """
    Mixin that verifies a user is logged in and is a superuser.
    This is used to restrict access to certain views to administrators.
    """
    def dispatch(self, request, *args, **kwargs):
        # Check if the user is authenticated and is a superuser
        if not request.user.is_authenticated or not request.user.is_superuser:
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)

# This helper function is still useful for simple, non-CBV views
def is_superuser(user):
    """Checks if a user is a superuser."""
    return user.is_superuser


# --- Token API Views ---
class ObtainTokenView(APIView):
    """
    An API endpoint to exchange an authorization code for a JWT.
    This view is a placeholder and should be configured with your
    universal authentication system's details.
    """
    def post(self, request, *args, **kwargs):
        code = request.data.get('code')
        client_id = request.data.get('client_id')
        redirect_uri = request.data.get('redirect_uri')

        # Basic validation for required fields
        if not all([code, client_id, redirect_uri]):
            return Response(
                {"error": "Missing code, client_id, or redirect_uri"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # This part assumes a remote token exchange endpoint.
        token_url = "https://universal-auth.example.com/api/token/"
        payload = {
            'code': code,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
        }
        headers = {'Content-Type': 'application/json'}
        
        try:
            # Make the request to the external auth service
            response = requests.post(token_url, data=json.dumps(payload), headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes
            universal_token_data = response.json()
        except requests.exceptions.RequestException as e:
            return Response(
                {"error": f"Failed to get token from universal auth: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        try:
            # Decode the ID token to get user information
            decoded_token = jwt.decode(
                universal_token_data['id_token'],
                algorithms=['RS256'],
                audience=client_id,
                key="YOUR_UNIVERSAL_AUTH_PUBLIC_KEY" # Replace with your actual public key
            )
            email = decoded_token.get('email')
            username = decoded_token.get('username')
        except jwt.InvalidTokenError as e:
            return Response(
                {"error": f"Invalid universal token: {str(e)}"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        # Get or create the Django user based on the decoded token info
        user, created = User.objects.get_or_create(username=username, email=email)
        if created:
            user.set_unusable_password()
            user.save()
            
        # Generate and return a Simple JWT token for the Django user
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)


class RefreshTokenView(TokenRefreshView):
    """
    A simple view that uses Simple JWT's built-in refresh token logic
    to get a new access token.
    """
    pass

# --- Function-based Views for Authentication ---

def login_view(request):
    """
    Custom login view for the file manager app.
    """
    error = None
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('index')
        else:
            error = 'Invalid username or password.'
    return render(request, 'registration/login.html', {'error': error})

from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    """
    Logs out the user and redirects to the login page.
    """
    logout(request)
    return redirect('file_manager_app:login')

# --- General Application Views (Function-based views are appropriate here) ---

@login_required
def dashboard(request):
    """
    Displays the main dashboard with quick statistics.
    """
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


@login_required
def search_results(request):
    """
    Performs a full-text search across various models.
    """
    query = request.GET.get('q', '')
    incoming_results = []
    outgoing_results = []
    filing_results = []
    
    if query:
        # Using Q objects for a more complex OR query
        incoming_results = IncomingLetter.objects.filter(
            Q(subject__icontains=query) | Q(reference__icontains=query) |
            Q(author__icontains=query) | Q(receiving_officer__username__icontains=query)
        ).distinct()
        
        outgoing_results = OutgoingLetter.objects.filter(
            Q(subject__icontains=query) | Q(reference__icontains=query) |
            Q(recipient__icontains=query) | Q(sent_by__username__icontains=query)
        ).distinct()
        
        filing_results = Filing.objects.filter(
            Q(file_name__icontains=query) | Q(file_reference__icontains=query) |
            Q(serial_number__icontains=query) | Q(receiving_department__icontains=query) |
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
    """
    Displays a dashboard for various reports.
    """
    return render(request, 'reports/report_dashboard.html')


@login_required
def letter_volume_report(request):
    """
    Generates a report on the volume of incoming and outgoing letters over time.
    """
    # Note: This uses SQLite-specific `strftime` and might need adjustment for other databases.
    incoming_counts = IncomingLetter.objects.extra(
        {'month': "strftime('%%Y-%%m', received_date)"}
    ).values('month').annotate(count=Count('id')).order_by('month')
    
    outgoing_counts = OutgoingLetter.objects.extra(
        {'month': "strftime('%%Y-%%m', date_sent)"}
    ).values('month').annotate(count=Count('id')).order_by('month')
    
    context = {
        'incoming_counts': incoming_counts,
        'outgoing_counts': outgoing_counts,
    }
    return render(request, 'reports/letter_volume_report.html', context)


@login_required
def filing_type_report(request):
    """
    Generates a paginated report of all filings.
    """
    filings = Filing.objects.all().order_by('-receiving_date')
    paginator = Paginator(filings, 20)
    page = request.GET.get('page')
    
    try:
        filing_list = paginator.page(page)
    except PageNotAnInteger:
        filing_list = paginator.page(1)
    except EmptyPage:
        filing_list = paginator.page(paginator.num_pages)
        
    context = {'filing_list': filing_list}
    return render(request, 'reports/filing_type_report.html', context)


@login_required
def incoming_letter_print_and_move(request, pk):
    """
    A specific business process that copies an incoming letter to an outgoing letter.
    This is best as a function-based view due to its specific logic.
    """
    incoming_letter = get_object_or_404(IncomingLetter, pk=pk)
    
    # Create the new outgoing letter from the incoming letter's data
    outgoing_letter = OutgoingLetter.objects.create(
        reference=incoming_letter.reference,
        subject=incoming_letter.subject,
        recipient=incoming_letter.author,
        date_sent=timezone.now(),
        sent_by=incoming_letter.receiving_officer,
        serial_number=f"OUT-{incoming_letter.serial_number}",
        remarks=incoming_letter.remarks,
        scanned_copy=incoming_letter.scanned_copy,
    )
    
    # "Delete" the incoming letter, which moves it to the archive via the `delete_file_soft` utility
    incoming_letter.delete()
    
    messages.success(request, 'Letter processed and moved to outgoing letters.')
    return redirect('file_manager_app:outgoing_letter_detail', pk=outgoing_letter.pk)


@login_required
def outgoing_letter_receipt(request, pk):
    """
    Displays the receipt for a specific outgoing letter.
    """
    letter = get_object_or_404(OutgoingLetter, pk=pk)
    return render(request, 'outgoing_letters/outgoing_letter_receipt.html', {'letter': letter})


# --- Custom Error Views ---
def custom_403_view(request, exception):
    """Renders the 403 Forbidden template."""
    return render(request, '403.html', status=403)

def custom_404_view(request, exception):
    """Renders the 404 Not Found template."""
    return render(request, '404.html', status=404)

def custom_500_view(request):
    """Renders the 500 Server Error template."""
    return render(request, '500.html', status=500)


# -----------------------------------------------------------
# --- User Management Views (Class-Based Views) ---
# -----------------------------------------------------------
class UserRegisterView(CreateView):
    """
    A view for user registration, using a custom form.
    Handles form submission and redirects on success.
    """
    model = User
    form_class = CustomUserCreationForm
    template_name = 'registration/register.html'
    success_url = reverse_lazy('index')  # Redirect to index after registration

    def form_valid(self, form):
        response = super().form_valid(form)
        # Log the user in after successful registration
        login(self.request, self.object)
        messages.success(self.request, f"Account created for {self.object.username}!")
        return response


class ProfileDetailView(DetailView):
    """
    Displays the current user's profile details.
    Uses `get_object` to always get the profile of the logged-in user.
    """
    model = User
    template_name = 'users/profile_detail.html'

    def get_object(self, queryset=None):
        return self.request.user


class ProfileEditView(UpdateView):
    """
    Allows the user to edit their own profile.
    Uses `get_object` to ensure the correct user is updated.
    """
    model = User
    form_class = CustomUserChangeForm
    template_name = 'users/profile_edit.html'
    success_url = reverse_lazy('file_manager_app:profile_detail')

    def get_object(self, queryset=None):
        return self.request.user


class UserListView(SuperuserRequiredMixin, ListView):
    """
    Lists all users. Only accessible by superusers via the mixin.
    """
    model = User
    template_name = 'users/user_list.html'
    context_object_name = 'users'
    paginate_by = 20


class UserDetailView(SuperuserRequiredMixin, DetailView):
    """
    Displays the details of a specific user.
    """
    model = User
    template_name = 'users/user_detail.html'
    context_object_name = 'user_obj'


class UserEditView(SuperuserRequiredMixin, UpdateView):
    """
    Allows a superuser to edit another user's details.
    """
    model = User
    form_class = CustomUserChangeForm
    template_name = 'users/user_edit.html'
    context_object_name = 'user_obj'

    def get_success_url(self):
        return reverse_lazy('file_manager_app:user_detail', kwargs={'pk': self.object.pk})


class UserDeleteView(SuperuserRequiredMixin, DeleteView):
    """
    Allows a superuser to delete another user.
    """
    model = User
    template_name = 'users/user_confirm_delete.html'
    context_object_name = 'user_obj'
    success_url = reverse_lazy('file_manager_app:user_list')


# -----------------------------------------------------------------
# --- Incoming Letters Views (Class-Based Views) ---
# -----------------------------------------------------------------
@login_required
def incoming_letter_list(request):
    letters = IncomingLetter.objects.all().order_by('-received_date')
    paginator = Paginator(letters, 20)
    page = request.GET.get('page')
    try:
        letter_list = paginator.page(page)
    except PageNotAnInteger:
        letter_list = paginator.page(1)
    except EmptyPage:
        letter_list = paginator.page(paginator.num_pages)
    context = {'letter_list': letter_list}
    return render(request, 'incoming_letters/incoming_letter_list.html', context)

@login_required
def incoming_letter_detail(request, pk):
    letter = get_object_or_404(IncomingLetter.objects.select_related('receiving_officer', 'signed_by'), pk=pk)
    context = {'incoming_letter': letter}
    return render(request, 'incoming_letters/incoming_letter_detail.html', context)

@login_required
def incoming_letter_form(request, pk=None):
    incoming_letter = None
    if pk:
        incoming_letter = get_object_or_404(IncomingLetter, pk=pk)
    if request.user.is_superuser:
        receiving_officers = User.objects.all().order_by('username')
    else:
        receiving_officers = User.objects.filter(pk=request.user.pk)
    if request.method == 'POST':
        data = request.POST.copy()
        if not request.user.is_superuser:
            data['receiving_officer'] = request.user.pk
        if not incoming_letter:
            if IncomingLetter.objects.filter(reference=data['reference']).exists():
                context = {
                    'incoming_letter': incoming_letter,
                    'receiving_officers': receiving_officers,
                    'all_users': User.objects.all().order_by('username'),
                    'error': 'An incoming letter with this reference already exists. Please use a unique reference.'
                }
                return render(request, 'incoming_letters/incoming_letter_form.html', context)
        if incoming_letter:
            incoming_letter.received_date = data.get('received_date', incoming_letter.received_date)
            incoming_letter.serial_number = data.get('serial_number', incoming_letter.serial_number)
            incoming_letter.date_of_letter = data.get('date_of_letter', incoming_letter.date_of_letter)
            incoming_letter.reference = data.get('reference', incoming_letter.reference)
            incoming_letter.subject = data.get('subject', incoming_letter.subject)
            incoming_letter.author = data.get('author', incoming_letter.author)
            incoming_letter.receiving_officer = get_object_or_404(User, pk=data['receiving_officer'])
            incoming_letter.remarks = data.get('remarks', incoming_letter.remarks)
            incoming_letter.sender = data.get('sender', incoming_letter.sender)
            if 'scanned_copy' in request.FILES:
                incoming_letter.scanned_copy = request.FILES['scanned_copy']
            incoming_letter.save()
        else:
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
        return redirect('file_manager_app:incoming_letter_list')
    else:
        context = {
            'incoming_letter': incoming_letter,
            'receiving_officers': receiving_officers,
            'all_users': User.objects.all().order_by('username'),
        }
        return render(request, 'incoming_letters/incoming_letter_form.html', context)

@login_required
def incoming_letter_confirm_delete(request, pk):
    incoming_letter = get_object_or_404(IncomingLetter, pk=pk)
    if request.method == 'POST':
        # Soft delete scanned copy if exists
        if incoming_letter.scanned_copy:
            delete_file_soft(incoming_letter.scanned_copy.path)
        incoming_letter.delete()
        return redirect('file_manager_app:archived_files_list')
    context = {'incoming_letter': incoming_letter}
    return render(request, 'incoming_letters/incoming_letter_confirm_delete.html', context)


# -----------------------------------------------------------------
# --- Outgoing Letters Views (Class-Based Views) ---
# -----------------------------------------------------------------
@login_required
def outgoing_letter_list(request):
    letters = OutgoingLetter.objects.all().order_by('-date_sent')
    paginator = Paginator(letters, 20)
    page = request.GET.get('page')
    try:
        letter_list = paginator.page(page)
    except PageNotAnInteger:
        letter_list = paginator.page(1)
    except EmptyPage:
        letter_list = paginator.page(paginator.num_pages)
    context = {'letter_list': letter_list}
    return render(request, 'outgoing_letters/outgoing_letter_list.html', context)

@login_required
def outgoing_letter_detail(request, pk):
    letter = get_object_or_404(OutgoingLetter.objects.select_related('sent_by'), pk=pk)
    context = {'outgoing_letter': letter}
    return render(request, 'outgoing_letters/outgoing_letter_detail.html', context)

@login_required
def outgoing_letter_form(request, pk=None):
    outgoing_letter = None
    if pk:
        outgoing_letter = get_object_or_404(OutgoingLetter, pk=pk)
    all_users = User.objects.all().order_by('username')
    if request.method == 'POST':
        sent_by_user = get_object_or_404(User, pk=request.POST['sent_by']) if request.POST.get('sent_by') else None
        if outgoing_letter:
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
        else:
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
        return redirect('file_manager_app:outgoing_letter_list')
    else:
        context = {
            'outgoing_letter': outgoing_letter,
            'all_users': all_users,
        }
        return render(request, 'outgoing_letters/outgoing_letter_form.html', context)

@login_required
def outgoing_letter_confirm_delete(request, pk):
    outgoing_letter = get_object_or_404(OutgoingLetter, pk=pk)
    if request.method == 'POST':
        # Soft delete scanned copy if exists
        if outgoing_letter.scanned_copy:
            delete_file_soft(outgoing_letter.scanned_copy.path)
        outgoing_letter.delete()
        return redirect('file_manager_app:archived_files_list')
    context = {'outgoing_letter': outgoing_letter}
    return render(request, 'outgoing_letters/outgoing_letter_confirm_delete.html', context)

@login_required
def outgoing_letter_receipt(request, pk):
    outgoing_letter = get_object_or_404(OutgoingLetter.objects.select_related('sent_by'), pk=pk)
    context = {'outgoing_letter': outgoing_letter}
    return render(request, 'outgoing_letters/outgoing_letter_receipt.html', context)



# -----------------------------------------------------------
# --- Filings Views (Class-Based Views) ---
# -----------------------------------------------------------
@login_required
def filing_list(request):
    filings = Filing.objects.all().order_by('-receiving_date')
    paginator = Paginator(filings, 20)
    page = request.GET.get('page')
    try:
        filing_list = paginator.page(page)
    except PageNotAnInteger:
        filing_list = paginator.page(1)
    except EmptyPage:
        filing_list = paginator.page(paginator.num_pages)
    context = {'filing_list': filing_list}
    return render(request, 'filings/filing_list.html', context)

@login_required
def filing_detail(request, pk):
    filing = get_object_or_404(Filing.objects.select_related('receiving_officer'), pk=pk)
    filing_documents = filing.documents.all()
    context = {
        'filing': filing,
        'filing_documents': filing_documents,
    }
    return render(request, 'filings/filing_detail.html', context)

@login_required
def filing_form(request, pk=None):
    filing = None
    if pk:
        filing = get_object_or_404(Filing, pk=pk)
    if request.user.is_superuser:
        receiving_officers = User.objects.all().order_by('username')
    else:
        receiving_officers = User.objects.filter(pk=request.user.pk)
    if request.method == 'POST':
        data = request.POST.copy()
        if not request.user.is_superuser:
            data['receiving_officer'] = request.user.pk
        receiving_officer_obj = get_object_or_404(User, pk=data['receiving_officer'])
        if filing:
            filing.file_reference = data.get('file_reference', filing.file_reference)
            filing.file_name = data.get('file_name', filing.file_name)
            filing.serial_number = data.get('serial_number', filing.serial_number)
            filing.receiving_department = data.get('receiving_department', filing.receiving_department)
            filing.receiving_officer = receiving_officer_obj
            filing.receiving_date = data.get('receiving_date', filing.receiving_date)
            if 'scanned_copy' in request.FILES:
                filing.scanned_copy = request.FILES['scanned_copy']
            filing.save()
        else:
            Filing.objects.create(
                file_reference=data['file_reference'],
                file_name=data['file_name'],
                serial_number=data['serial_number'],
                receiving_department=data['receiving_department'],
                receiving_officer=receiving_officer_obj,
                receiving_date=data['receiving_date'],
                scanned_copy=request.FILES.get('scanned_copy'),
            )
        return redirect('file_manager_app:filing_list')
    else:
        context = {
            'filing': filing,
            'receiving_officers': receiving_officers,
        }
        return render(request, 'filings/filing_form.html', context)

@login_required
def filing_confirm_delete(request, pk):
    filing = get_object_or_404(Filing, pk=pk)
    if request.method == 'POST':
        # Soft delete scanned copy if exists
        if filing.scanned_copy:
            delete_file_soft(filing.scanned_copy.path)
        filing.delete()
        return redirect('file_manager_app:archived_files_list')
    context = {'filing': filing}
    return render(request, 'filings/filing_confirm_delete.html', context)

@login_required
def filing_document_form(request, filing_pk):
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
            filing_document = FilingDocument(
                filing=filing,
                document_name=document_name,
                folio_number=folio_number,
                uploaded_file=uploaded_file
            )
            filing_document.full_clean()
            filing_document.save()
            return redirect('file_manager_app:filing_detail', pk=filing.pk)
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
    filing_document = get_object_or_404(FilingDocument, pk=pk)
    filing_pk = filing_document.filing.pk
    if request.method == 'POST':
        # Soft delete uploaded file if exists
        if filing_document.uploaded_file:
            delete_file_soft(filing_document.uploaded_file.path)
        filing_document.delete()
        return redirect('file_manager_app:archived_files_list')
    context = {'filing_document': filing_document}
    return render(request, 'filings/filing_document_confirm_delete.html', context)

class FilingDocumentDeleteView(DeleteView):
    """
    Handles the deletion of a filing document.
    Note: The `delete_file_soft` is called from the `models.py` `pre_delete` signal.
    """
    model = FilingDocument
    template_name = 'filings/filing_document_confirm_delete.html'
    context_object_name = 'filing_document'

    def get_success_url(self):
        # Redirect back to the parent filing's detail page
        return reverse_lazy('file_manager_app:filing_detail', kwargs={'pk': self.object.filing.pk})

    def form_valid(self, form):
        messages.success(self.request, 'Document deleted and archived successfully.')
        return super().form_valid(form)


# -----------------------------------------------------------
# --- Archived Files Views  ---
# -----------------------------------------------------------
@login_required
def archived_files_list(request):
    setup_directories()  # Ensure archive dir exists
    archived_incoming = ArchivedFile.objects.filter(category='incoming', restored=False)
    archived_outgoing = ArchivedFile.objects.filter(category='outgoing', restored=False)
    archived_filing = ArchivedFile.objects.filter(category='filing', restored=False)
    context = {
        'archived_incoming': archived_incoming,
        'archived_outgoing': archived_outgoing,
        'archived_filing': archived_filing,
    }
    return render(request, 'files/archived_files_list.html', context)

@login_required
def restore_archived_file(request, pk):
    archived_file = get_object_or_404(ArchivedFile, pk=pk, restored=False)
    if request.method == 'POST':
        success = restore_file(archived_file.archived_name)
        if success:
            archived_file.restored = True
            archived_file.save()
        return redirect('file_manager_app:archived_files_list')
    return render(request, 'files/restore_confirm.html', {'archived_file': archived_file})



# -----------------------------------------------------------
# --- other Views  ---
# -----------------------------------------------------------

@login_required
def search_results(request):
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
    return render(request, 'reports/report_dashboard.html')

@login_required
def letter_volume_report(request):
    incoming_counts = IncomingLetter.objects.extra({'month': "strftime('%%Y-%%m', received_date)"}).values('month').annotate(count=Count('id')).order_by('month')
    outgoing_counts = OutgoingLetter.objects.extra({'month': "strftime('%%Y-%%m', date_sent)"}).values('month').annotate(count=Count('id')).order_by('month')
    context = {
        'incoming_counts': incoming_counts,
        'outgoing_counts': outgoing_counts,
    }
    return render(request, 'reports/letter_volume_report.html', context)

@login_required
def filing_type_report(request):
    filings = Filing.objects.all().order_by('-receiving_date')
    paginator = Paginator(filings, 20)
    page = request.GET.get('page')
    try:
        filing_list = paginator.page(page)
    except PageNotAnInteger:
        filing_list = paginator.page(1)
    except EmptyPage:
        filing_list = paginator.page(paginator.num_pages)
    context = {'filing_list': filing_list}
    return render(request, 'reports/filing_type_report.html', context)



# --- Print and Move Incoming Letter to Outgoing ---
@login_required
def incoming_letter_print_and_move(request, pk):
    incoming_letter = get_object_or_404(IncomingLetter, pk=pk)
    receipt_html = render_to_string('outgoing_letters/outgoing_letter_receipt.html', {'outgoing_letter': incoming_letter})
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmp:
        tmp.write(receipt_html.encode('utf-8'))
        tmp_path = tmp.name
    # You must have a receipt_file field in OutgoingLetter for this to work
    outgoing_letter = OutgoingLetter.objects.create(
        reference=incoming_letter.reference,
        subject=incoming_letter.subject,
        recipient=incoming_letter.author,
        date_sent=timezone.now(),
        sent_by=incoming_letter.receiving_officer,
        serial_number=f"OUT-{incoming_letter.serial_number}",
        remarks=incoming_letter.remarks,
        scanned_copy=incoming_letter.scanned_copy,
        # receipt_file=tmp_path  # Uncomment if you have this field
    )
    incoming_letter.delete()
    return redirect('file_manager_app:outgoing_letter_detail', pk=outgoing_letter.pk)

@login_required
def restore_archived_file(request, pk):
    archived_file = get_object_or_404(ArchivedFile, pk=pk, restored=False)
    if request.method == 'POST':
        success = restore_file(archived_file.archived_name)
        if success:
            archived_file.restored = True
            archived_file.save()
        return redirect('file_manager_app:archived_files_list')
    return render(request, 'files/restore_confirm.html', {'archived_file': archived_file})

def custom_403_view(request, exception):
    """
    Renders a custom 403 Forbidden error page.
    """
    return render(request, 'file_manager_app/error.html', {'status_code': 403, 'message': 'You do not have permission to access this page.'}, status=403)

def custom_404_view(request, exception):
    """
    Renders a custom 404 Not Found error page.
    """
    return render(request, 'file_manager_app/error.html', {'status_code': 404, 'message': 'The page you are looking for was not found.'}, status=404)

def custom_500_view(request):
    """
    Renders a custom 500 Server Error page.
    """
    return render(request, 'file_manager_app/error.html', {'status_code': 500, 'message': 'An unexpected server error occurred.'}, status=500)
