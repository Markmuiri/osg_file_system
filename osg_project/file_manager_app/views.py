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
    template_name = 'users/register.html'
    success_url = reverse_lazy('login') # Assuming you have a login view

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
class IncomingLetterListView(ListView):
    """
    Lists all incoming letters.
    """
    model = IncomingLetter
    template_name = 'incoming_letters/incoming_letter_list.html'
    context_object_name = 'letter_list'
    paginate_by = 20


class IncomingLetterDetailView(DetailView):
    """
    Displays the details of an incoming letter.
    """
    model = IncomingLetter
    template_name = 'incoming_letters/incoming_letter_detail.html'
    context_object_name = 'incoming_letter'


class IncomingLetterCreateView(CreateView):
    """
    Handles the creation of a new incoming letter.
    """
    model = IncomingLetter
    form_class = IncomingLetterForm
    template_name = 'incoming_letters/incoming_letter_form.html'
    success_url = reverse_lazy('file_manager_app:incoming_letter_list')

    def form_valid(self, form):
        # Attach the current user as the receiving officer automatically
        form.instance.receiving_officer = self.request.user
        messages.success(self.request, 'Incoming letter created successfully.')
        return super().form_valid(form)


class IncomingLetterUpdateView(UpdateView):
    """
    Handles the update of an existing incoming letter.
    """
    model = IncomingLetter
    form_class = IncomingLetterForm
    template_name = 'incoming_letters/incoming_letter_form.html'
    success_url = reverse_lazy('file_manager_app:incoming_letter_list')

    def form_valid(self, form):
        messages.success(self.request, 'Incoming letter updated successfully.')
        return super().form_valid(form)


class IncomingLetterDeleteView(DeleteView):
    """
    Handles the deletion of an incoming letter.
    Note: The `delete_file_soft` is called from the `models.py` `pre_delete` signal.
    """
    model = IncomingLetter
    template_name = 'incoming_letters/incoming_letter_confirm_delete.html'
    context_object_name = 'incoming_letter'
    success_url = reverse_lazy('file_manager_app:archived_files_list')

    def form_valid(self, form):
        messages.success(self.request, 'Incoming letter deleted and archived successfully.')
        return super().form_valid(form)


# -----------------------------------------------------------------
# --- Outgoing Letters Views (Class-Based Views) ---
# -----------------------------------------------------------------
class OutgoingLetterListView(ListView):
    """
    Lists all outgoing letters.
    """
    model = OutgoingLetter
    template_name = 'outgoing_letters/outgoing_letter_list.html'
    context_object_name = 'letter_list'
    paginate_by = 20


class OutgoingLetterDetailView(DetailView):
    """
    Displays the details of an outgoing letter.
    """
    model = OutgoingLetter
    template_name = 'outgoing_letters/outgoing_letter_detail.html'
    context_object_name = 'outgoing_letter'


class OutgoingLetterCreateView(CreateView):
    """
    Handles the creation of a new outgoing letter.
    """
    model = OutgoingLetter
    form_class = OutgoingLetterForm
    template_name = 'outgoing_letters/outgoing_letter_form.html'
    success_url = reverse_lazy('file_manager_app:outgoing_letter_list')

    def form_valid(self, form):
        # Attach the current user as the sender automatically
        form.instance.sent_by = self.request.user
        messages.success(self.request, 'Outgoing letter created successfully.')
        return super().form_valid(form)


class OutgoingLetterUpdateView(UpdateView):
    """
    Handles the update of an existing outgoing letter.
    """
    model = OutgoingLetter
    form_class = OutgoingLetterForm
    template_name = 'outgoing_letters/outgoing_letter_form.html'
    success_url = reverse_lazy('file_manager_app:outgoing_letter_list')

    def form_valid(self, form):
        messages.success(self.request, 'Outgoing letter updated successfully.')
        return super().form_valid(form)


class OutgoingLetterDeleteView(DeleteView):
    """
    Handles the deletion of an outgoing letter.
    Note: The `delete_file_soft` is called from the `models.py` `pre_delete` signal.
    """
    model = OutgoingLetter
    template_name = 'outgoing_letters/outgoing_letter_confirm_delete.html'
    context_object_name = 'outgoing_letter'
    success_url = reverse_lazy('file_manager_app:archived_files_list')

    def form_valid(self, form):
        messages.success(self.request, 'Outgoing letter deleted and archived successfully.')
        return super().form_valid(form)


# -----------------------------------------------------------
# --- Filings Views (Class-Based Views) ---
# -----------------------------------------------------------
class FilingListView(ListView):
    """
    Lists all filings.
    """
    model = Filing
    template_name = 'filings/filing_list.html'
    context_object_name = 'filing_list'
    paginate_by = 20


class FilingDetailView(DetailView):
    """
    Displays the details of a specific filing and its documents.
    """
    model = Filing
    template_name = 'filings/filing_detail.html'
    context_object_name = 'filing'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Fetch all related documents for this filing
        context['filing_documents'] = self.object.documents.all()
        return context


class FilingCreateView(CreateView):
    """
    Handles the creation of a new filing.
    """
    model = Filing
    form_class = FilingForm
    template_name = 'filings/filing_form.html'
    success_url = reverse_lazy('file_manager_app:filing_list')

    def form_valid(self, form):
        # Attach the current user as the receiving officer automatically
        form.instance.receiving_officer = self.request.user
        messages.success(self.request, 'Filing created successfully.')
        return super().form_valid(form)


class FilingUpdateView(UpdateView):
    """
    Handles the update of an existing filing.
    """
    model = Filing
    form_class = FilingForm
    template_name = 'filings/filing_form.html'
    success_url = reverse_lazy('file_manager_app:filing_list')

    def form_valid(self, form):
        messages.success(self.request, 'Filing updated successfully.')
        return super().form_valid(form)


class FilingDeleteView(DeleteView):
    """
    Handles the deletion of a filing.
    Note: The `delete_file_soft` is called from the `models.py` `pre_delete` signal.
    """
    model = Filing
    template_name = 'filings/filing_confirm_delete.html'
    context_object_name = 'filing'
    success_url = reverse_lazy('file_manager_app:archived_files_list')

    def form_valid(self, form):
        messages.success(self.request, 'Filing deleted and archived successfully.')
        return super().form_valid(form)


class FilingDocumentCreateView(CreateView):
    """
    Handles the creation of a new document for a specific filing.
    """
    model = FilingDocument
    form_class = FilingDocumentForm
    template_name = 'filings/filing_document_form.html'

    def get_success_url(self):
        # Redirect back to the filing detail page after creating a document
        return reverse_lazy('file_manager_app:filing_detail', kwargs={'pk': self.kwargs['filing_pk']})

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add the parent filing object to the context
        context['filing'] = get_object_or_404(Filing, pk=self.kwargs['filing_pk'])
        return context

    def form_valid(self, form):
        # Associate the new document with the correct filing
        filing = get_object_or_404(Filing, pk=self.kwargs['filing_pk'])
        form.instance.filing = filing
        messages.success(self.request, 'Document created successfully.')
        return super().form_valid(form)


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
# --- Archived Files Views (Class-Based Views) ---
# -----------------------------------------------------------
class ArchivedFilesListView(ListView):
    """
    Lists all archived files, separated by category.
    """
    model = ArchivedFile
    template_name = 'files/archived_files_list.html'
    context_object_name = 'archived_files'
    
    def get_queryset(self):
        # We need to filter the queryset to get non-restored files
        return ArchivedFile.objects.filter(restored=False)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Separate the queryset into categories for easier template rendering
        context['archived_incoming'] = context['archived_files'].filter(category='incoming')
        context['archived_outgoing'] = context['archived_files'].filter(category='outgoing')
        context['archived_filing'] = context['archived_files'].filter(category='filing')
        return context


class RestoreArchivedFileView(UpdateView):
    """
    Handles the restoration of an archived file.
    """
    model = ArchivedFile
    fields = []  # No fields are needed for a simple restore action
    template_name = 'files/restore_confirm.html'
    success_url = reverse_lazy('file_manager_app:archived_files_list')

    def form_valid(self, form):
        # Call the helper function to restore the file to its original location
        success = restore_file(self.object.archived_name)
        if success:
            # Mark the file as restored in the database
            self.object.restored = True
            self.object.save()
            messages.success(self.request, f"File '{self.object.original_name}' restored successfully.")
        else:
            messages.error(self.request, f"Failed to restore file '{self.object.original_name}'.")
        return super().form_valid(form)

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
