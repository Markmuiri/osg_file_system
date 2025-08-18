# file_manager_app/forms.py

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, PasswordChangeForm
from .models import Profile, IncomingLetter, OutgoingLetter, Filing, FilingDocument, ArchivedFile
from django.forms import inlineformset_factory

# --- Mixin for shared form logic ---

class UserBaseFormMixin:
    """
    A mixin to add the profile fields to the user forms.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            try:
                self.fields['employee_number'].initial = self.instance.profile.employee_number
                self.fields['role'].initial = self.instance.profile.role
                self.fields['profile_picture'].initial = self.instance.profile.profile_picture
            except Profile.DoesNotExist:
                pass

    def save(self, commit=True):
        user = super().save(commit=False)
        user.save()
        profile, created = Profile.objects.get_or_create(user=user)
        profile.employee_number = self.cleaned_data.get('employee_number')
        profile.role = self.cleaned_data.get('role')
        if 'profile_picture' in self.cleaned_data:
            profile.profile_picture = self.cleaned_data['profile_picture']
        if commit:
            profile.save()
        return user


# --- Custom User Forms inheriting from Django's built-in forms and our mixin ---

class CustomUserCreationForm(UserBaseFormMixin, UserCreationForm):
    """
    A custom user creation form that includes profile fields.
    """
    employee_number = forms.CharField(max_length=50)
    role = forms.ChoiceField(choices=Profile.ROLE_CHOICES)
    profile_picture = forms.ImageField(required=False)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = (
            'username', 'first_name', 'last_name', 'email', 
            'employee_number', 'role', 'profile_picture',
        )


class CustomUserChangeForm(UserBaseFormMixin, UserChangeForm):
    """
    A custom user change form that includes profile fields.
    """
    employee_number = forms.CharField(max_length=50)
    role = forms.ChoiceField(choices=Profile.ROLE_CHOICES)
    profile_picture = forms.ImageField(required=False)

    class Meta(UserChangeForm.Meta):
        model = User
        fields = (
            'username', 'first_name', 'last_name', 'email', 'is_active', 
            'is_staff', 'is_superuser', 'groups', 'user_permissions',
            'employee_number', 'role', 'profile_picture',
        )


class CustomPasswordChangeForm(PasswordChangeForm):
    """
    A custom password change form.
    """
    # This form doesn't need a Meta class since it doesn't add any new fields.
    # It inherits all necessary logic directly from PasswordChangeForm.
    pass


# --- Your Existing Form Classes ---

class IncomingLetterForm(forms.ModelForm):
    class Meta:
        model = IncomingLetter
        fields = '__all__'

class OutgoingLetterForm(forms.ModelForm):
    class Meta:
        model = OutgoingLetter
        fields = '__all__'

class FilingForm(forms.ModelForm):
    class Meta:
        model = Filing
        fields = '__all__'

class FilingDocumentForm(forms.ModelForm):
    class Meta:
        model = FilingDocument
        fields = '__all__'

class ArchivedFileForm(forms.ModelForm):
    class Meta:
        model = ArchivedFile
        fields = '__all__'

FilingDocumentFormSet = inlineformset_factory(Filing, FilingDocument, form=FilingDocumentForm, extra=1, can_delete=True)
