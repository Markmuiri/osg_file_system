# file_manager_app/forms.py

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.core.exceptions import ValidationError

from .models import (
    Profile, IncomingLetter, OutgoingLetter,
    Filing, FilingDocument,
    validate_pdf, validate_csv_excel # Import custom validators
)

# --- Common Widget Attributes for Outlined, Modern Input Fields ---
# These attributes are applied to most text, number, date, and email input fields
COMMON_INPUT_WIDGET_ATTRS = {
    'class': 'block py-2.5 px-0 w-full text-sm text-gray-900 bg-transparent border-0 border-b-2 border-gray-300 appearance-none focus:outline-none focus:ring-0 focus:border-blue-600 peer',
    'placeholder': ' ', # Required for the floating label effect
}

# Attributes for TextArea fields
TEXTAREA_WIDGET_ATTRS = {
    'class': 'block py-2.5 px-0 w-full text-sm text-gray-900 bg-transparent border-0 border-b-2 border-gray-300 appearance-none focus:outline-none focus:ring-0 focus:border-blue-600 peer',
    'placeholder': ' ',
    'rows': 3, # Default rows for textareas
}

# Attributes for Select fields (dropdowns)
SELECT_WIDGET_ATTRS = {
    'class': 'block py-2.5 px-0 w-full text-sm text-gray-900 bg-transparent border-0 border-b-2 border-gray-300 appearance-none focus:outline-none focus:ring-0 focus:border-blue-600',
}

# Attributes for File/Image fields
FILE_INPUT_WIDGET_ATTRS = {
    'class': 'block w-full text-sm text-gray-900 border border-gray-300 rounded-lg cursor-pointer bg-gray-50 focus:outline-none file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100',
}

# --- User Management Forms ---

class UserRegistrationForm(forms.ModelForm):
    """
    Form for new user registration, combining User and Profile fields.
    """
    username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'username'}),
        label="Username"
    )
    first_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'given-name'}),
        label="First Name"
    )
    last_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'family-name'}),
        label="Last Name"
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'email'}),
        label="Email Address"
    )
    employee_number = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Employee Number"
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'new-password'}),
        label="Password"
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'new-password'}),
        label="Confirm Password"
    )
    profile_picture = forms.ImageField(
        required=False,
        widget=forms.ClearableFileInput(attrs=FILE_INPUT_WIDGET_ATTRS),
        label="Profile Picture"
    )

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email') # User fields handled here

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username=username).exists():
            raise ValidationError("This username is already taken.")
        return username

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise ValidationError("This email address is already registered.")
        return email

    def clean_employee_number(self):
        employee_number = self.cleaned_data['employee_number']
        if Profile.objects.filter(employee_number=employee_number).exists():
            raise ValidationError("An account with this employee number already exists.")
        return employee_number

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")

        if password and password_confirm and password != password_confirm:
            self.add_error('password_confirm', "Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
            # Profile is created by signal, now update its fields
            profile = user.profile
            profile.employee_number = self.cleaned_data["employee_number"]
            if 'profile_picture' in self.files:
                profile.profile_picture = self.cleaned_data['profile_picture']
            profile.save()
        return user


class UserProfileUpdateForm(forms.ModelForm):
    """
    Form for users to update their own profile information.
    """
    first_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'given-name'}),
        label="First Name"
    )
    last_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'family-name'}),
        label="Last Name"
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'email'}),
        label="Email Address"
    )
    employee_number = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Employee Number"
    )
    profile_picture = forms.ImageField(
        required=False,
        widget=forms.ClearableFileInput(attrs=FILE_INPUT_WIDGET_ATTRS),
        label="Profile Picture"
    )

    class Meta:
        model = Profile
        fields = ('employee_number', 'profile_picture')

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if self.user:
            self.fields['first_name'].initial = self.user.first_name
            self.fields['last_name'].initial = self.user.last_name
            self.fields['email'].initial = self.user.email

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exclude(pk=self.user.pk).exists():
            raise ValidationError("This email address is already registered by another user.")
        return email

    def clean_employee_number(self):
        employee_number = self.cleaned_data['employee_number']
        if Profile.objects.filter(employee_number=employee_number).exclude(pk=self.instance.pk).exists():
            raise ValidationError("An account with this employee number already exists.")
        return employee_number

    def save(self, commit=True):
        profile = super().save(commit=False)
        if self.user:
            self.user.first_name = self.cleaned_data['first_name']
            self.user.last_name = self.cleaned_data['last_name']
            self.user.email = self.cleaned_data['email']
            if commit:
                self.user.save()
        if commit:
            profile.save()
        return profile


class UserAdminEditForm(forms.ModelForm):
    """
    Form for superusers to edit other user profiles, including role.
    """
    first_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'given-name'}),
        label="First Name"
    )
    last_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'family-name'}),
        label="Last Name"
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'autocomplete': 'email'}),
        label="Email Address"
    )
    employee_number = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Employee Number"
    )
    profile_picture = forms.ImageField(
        required=False,
        widget=forms.ClearableFileInput(attrs=FILE_INPUT_WIDGET_ATTRS),
        label="Profile Picture"
    )
    role = forms.ChoiceField(
        choices=Profile.ROLE_CHOICES,
        widget=forms.Select(attrs=SELECT_WIDGET_ATTRS),
        label="Role"
    )

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email')

    def __init__(self, *args, **kwargs):
        self.user_obj = kwargs.pop('instance', None) # The user being edited
        super().__init__(*args, **kwargs)
        if self.user_obj:
            self.fields['username'].widget.attrs['readonly'] = True # Username is read-only
            self.fields['username'].widget.attrs['class'] += ' bg-gray-100 cursor-not-allowed'
            self.fields['employee_number'].initial = self.user_obj.profile.employee_number
            self.fields['profile_picture'].initial = self.user_obj.profile.profile_picture
            self.fields['role'].initial = self.user_obj.profile.role

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exclude(pk=self.user_obj.pk).exists():
            raise ValidationError("This email address is already registered by another user.")
        return email

    def clean_employee_number(self):
        employee_number = self.cleaned_data['employee_number']
        if Profile.objects.filter(employee_number=employee_number).exclude(pk=self.user_obj.profile.pk).exists():
            raise ValidationError("An account with this employee number already exists.")
        return employee_number

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
            profile = user.profile
            profile.employee_number = self.cleaned_data['employee_number']
            profile.role = self.cleaned_data['role']
            if 'profile_picture' in self.files:
                profile.profile_picture = self.cleaned_data['profile_picture']
            profile.save()
        return user


# --- Incoming Letters Forms ---

class IncomingLetterForm(forms.ModelForm):
    """
    Form for adding and editing IncomingLetter records.
    Filters receiving_officer based on superuser status.
    """
    received_date = forms.DateField(
        widget=forms.DateInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'type': 'date'}),
        label="Date Received"
    )
    serial_number = forms.CharField(
        max_length=50,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Serial No."
    )
    date_of_letter = forms.DateField(
        widget=forms.DateInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'type': 'date'}),
        label="Date of Letter"
    )
    reference = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Reference No."
    )
    subject = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Subject"
    )
    author = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Author/Sender"
    )
    remarks = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs=TEXTAREA_WIDGET_ATTRS),
        label="Remarks"
    )
    scanned_copy = forms.FileField(
        required=False,
        widget=forms.ClearableFileInput(attrs={**FILE_INPUT_WIDGET_ATTRS, 'accept': '.pdf'}),
        label="Scanned Copy (PDF, Max 5MB)",
        validators=[validate_pdf]
    )
    signed_by = forms.ModelChoiceField(
        queryset=User.objects.all().order_by('username'),
        required=False,
        widget=forms.Select(attrs=SELECT_WIDGET_ATTRS),
        label="Signed By (Officer)"
    )
    signed_at = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'type': 'date'}),
        label="Signed At"
    )
    is_actioned = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500'}),
        label="Letter Actioned?"
    )

    class Meta:
        model = IncomingLetter
        fields = [
            'received_date', 'serial_number', 'date_of_letter', 'reference',
            'subject', 'author', 'receiving_officer', 'remarks', 'scanned_copy',
            'signed_by', 'signed_at', 'is_actioned'
        ]
        # 'sender' and 'signature' are excluded if not directly managed by form or if signature is handled separately
        # 'signature' is an ImageField, might be uploaded via a separate process or admin.

        widgets = {
            'receiving_officer': forms.Select(attrs=SELECT_WIDGET_ATTRS),
        }

    def __init__(self, *args, **kwargs):
        self.request_user = kwargs.pop('user', None) # The logged-in user making the request
        super().__init__(*args, **kwargs)

        # Filter receiving_officer queryset based on superuser status
        if self.request_user and not self.request_user.is_superuser:
            self.fields['receiving_officer'].queryset = User.objects.filter(pk=self.request_user.pk)
            # If creating a new letter, pre-select the current user
            if not self.instance.pk: # If it's a new instance (not editing)
                self.fields['receiving_officer'].initial = self.request_user.pk
            # Make the field read-only for non-superusers (visually)
            self.fields['receiving_officer'].widget.attrs['disabled'] = 'disabled'
            self.fields['receiving_officer'].help_text = "As a non-superuser, you can only assign yourself."
        else:
            self.fields['receiving_officer'].queryset = User.objects.all().order_by('username')
            self.fields['receiving_officer'].help_text = "Select the officer responsible for this letter."

    def clean_serial_number(self):
        serial_number = self.cleaned_data['serial_number']
        if IncomingLetter.objects.filter(serial_number=serial_number).exclude(pk=self.instance.pk).exists():
            raise ValidationError("This serial number is already in use for an incoming letter.")
        return serial_number

    def clean_reference(self):
        reference = self.cleaned_data['reference']
        if IncomingLetter.objects.filter(reference=reference).exclude(pk=self.instance.pk).exists():
            raise ValidationError("This reference number is already in use for an incoming letter.")
        return reference

    def save(self, commit=True):
        # If receiving_officer was disabled, its value might not be in cleaned_data.
        # Manually set it back to the request user for non-superusers.
        if self.request_user and not self.request_user.is_superuser:
            self.instance.receiving_officer = self.request_user
        return super().save(commit)


# --- Outgoing Letters Forms ---

class OutgoingLetterForm(forms.ModelForm):
    """
    Form for adding and editing OutgoingLetter records.
    """
    date_sent = forms.DateField(
        widget=forms.DateInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'type': 'date'}),
        label="Date Sent"
    )
    serial_number = forms.CharField(
        max_length=50,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Serial No."
    )
    reference = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Reference No."
    )
    subject = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Subject"
    )
    recipient = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Recipient"
    )
    remarks = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs=TEXTAREA_WIDGET_ATTRS),
        label="Remarks"
    )
    scanned_copy = forms.FileField(
        required=False,
        widget=forms.ClearableFileInput(attrs={**FILE_INPUT_WIDGET_ATTRS, 'accept': '.pdf'}),
        label="Scanned Copy (PDF, Max 5MB)",
        validators=[validate_pdf]
    )

    class Meta:
        model = OutgoingLetter
        fields = [
            'date_sent', 'serial_number', 'reference', 'subject',
            'recipient', 'sent_by', 'scanned_copy', 'remarks'
        ]
        widgets = {
            'sent_by': forms.Select(attrs=SELECT_WIDGET_ATTRS),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Ensure 'sent_by' always has all users in its queryset
        self.fields['sent_by'].queryset = User.objects.all().order_by('username')

    def clean_serial_number(self):
        serial_number = self.cleaned_data['serial_number']
        if OutgoingLetter.objects.filter(serial_number=serial_number).exclude(pk=self.instance.pk).exists():
            raise ValidationError("This serial number is already in use for an outgoing letter.")
        return serial_number

    def clean_reference(self):
        reference = self.cleaned_data['reference']
        if OutgoingLetter.objects.filter(reference=reference).exclude(pk=self.instance.pk).exists():
            raise ValidationError("This reference number is already in use for an outgoing letter.")
        return reference


# --- Filings Forms ---

class FilingForm(forms.ModelForm):
    """
    Form for adding and editing Filing records.
    Filters receiving_officer based on superuser status.
    """
    file_reference = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="File Reference"
    )
    file_name = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="File Name"
    )
    serial_number = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Serial Number"
    )
    receiving_department = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Receiving Department"
    )
    receiving_date = forms.DateField(
        widget=forms.DateInput(attrs={**COMMON_INPUT_WIDGET_ATTRS, 'type': 'date'}),
        label="Receiving Date"
    )
    scanned_copy = forms.FileField(
        required=False,
        widget=forms.ClearableFileInput(attrs={**FILE_INPUT_WIDGET_ATTRS, 'accept': '.pdf'}),
        label="Main Scanned Copy (PDF, Max 5MB)",
        validators=[validate_pdf]
    )

    class Meta:
        model = Filing
        fields = [
            'file_reference', 'file_name', 'serial_number',
            'receiving_department', 'receiving_officer', 'receiving_date',
            'scanned_copy'
        ]
        widgets = {
            'receiving_officer': forms.Select(attrs=SELECT_WIDGET_ATTRS),
        }

    def __init__(self, *args, **kwargs):
        self.request_user = kwargs.pop('user', None) # The logged-in user making the request
        super().__init__(*args, **kwargs)

        # Filter receiving_officer queryset based on superuser status
        if self.request_user and not self.request_user.is_superuser:
            self.fields['receiving_officer'].queryset = User.objects.filter(pk=self.request_user.pk)
            # If creating a new filing, pre-select the current user
            if not self.instance.pk: # If it's a new instance (not editing)
                self.fields['receiving_officer'].initial = self.request_user.pk
            # Make the field read-only for non-superusers (visually)
            self.fields['receiving_officer'].widget.attrs['disabled'] = 'disabled'
            self.fields['receiving_officer'].help_text = "As a non-superuser, you can only assign yourself."
        else:
            self.fields['receiving_officer'].queryset = User.objects.all().order_by('username')
            self.fields['receiving_officer'].help_text = "Select the officer responsible for this filing."

    def clean_file_reference(self):
        file_reference = self.cleaned_data['file_reference']
        if Filing.objects.filter(file_reference=file_reference).exclude(pk=self.instance.pk).exists():
            raise ValidationError("This file reference is already in use for a filing.")
        return file_reference

    def clean_serial_number(self):
        serial_number = self.cleaned_data['serial_number']
        if Filing.objects.filter(serial_number=serial_number).exclude(pk=self.instance.pk).exists():
            raise ValidationError("This serial number is already in use for a filing.")
        return serial_number

    def save(self, commit=True):
        # If receiving_officer was disabled, its value might not be in cleaned_data.
        # Manually set it back to the request user for non-superusers.
        if self.request_user and not self.request_user.is_superuser:
            self.instance.receiving_officer = self.request_user
        return super().save(commit)


class FilingDocumentForm(forms.ModelForm):
    """
    Form for uploading documents to an existing Filing.
    Includes validation for CSV/Excel files.
    """
    document_name = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Document Name"
    )
    folio_number = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs=COMMON_INPUT_WIDGET_ATTRS),
        label="Folio Number"
    )
    uploaded_file = forms.FileField(
        widget=forms.ClearableFileInput(attrs={**FILE_INPUT_WIDGET_ATTRS, 'accept': '.csv, application/vnd.ms-excel, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}),
        label="Upload Document (CSV/Excel, Max 10MB)",
        validators=[validate_csv_excel]
    )

   
