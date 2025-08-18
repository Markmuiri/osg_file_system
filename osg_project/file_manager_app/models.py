# file_manager_app/models.py

from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError
from django.utils import timezone
import os
import datetime

# --- Custom Validators for File Uploads ---

def validate_pdf(value):
    """
    Validator to ensure the uploaded file is a PDF and within size limits.
    """
    file_extension = os.path.splitext(value.name)[1].lower()
    if file_extension != '.pdf':
        raise ValidationError('Only PDF files are allowed for scanned copies.')
    if value.size > 5 * 1024 * 1024:  # 5 MB limit
        raise ValidationError('PDF file size must be under 5MB.')

def validate_csv_excel(value):
    """
    Validator to ensure the uploaded file is a CSV or Excel format and within size limits.
    """
    file_extension = os.path.splitext(value.name)[1].lower()
    valid_extensions = ['.csv', '.xls', '.xlsx']
    if file_extension not in valid_extensions:
        raise ValidationError('Only CSV or Excel files (.csv, .xls, .xlsx) are allowed.')
    if value.size > 10 * 1024 * 1024:  # 10 MB limit for data files
        raise ValidationError('File size must be under 10MB.')

def validate_pdf_word(value):
    """
    Validator to ensure the uploaded file is a PDF or Word document and within size limits.
    """
    file_extension = os.path.splitext(value.name)[1].lower()
    valid_extensions = ['.pdf', '.docx', '.doc']
    if file_extension not in valid_extensions:
        raise ValidationError('Only PDF or Word documents are allowed.')
    if value.size > 5 * 1024 * 1024:  # 5 MB limit
        raise ValidationError('File size must be under 5MB.')


# --- User Profile Model (Required for forms to work) ---

class Profile(models.Model):
    """
    Extends the default Django User model with additional profile information.
    """
    ROLE_CHOICES = [
        ('superuser', 'Superuser'),
        ('officer', 'Officer'),
        ('intern', 'Intern'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    employee_number = models.CharField(max_length=50, unique=True, help_text="Unique employee number.")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='intern', help_text="The user's role in the organization.")
    profile_picture = models.ImageField(upload_to='profile_pics/', default='profile_pics/default.png', blank=True)

    def __str__(self):
        return self.user.username

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """
    Signal handler to create or update a user's profile automatically.
    """
    if created:
        Profile.objects.create(user=instance)
    instance.profile.save()

# --- Core File Management Models ---

class IncomingLetter(models.Model):
    """Model for incoming letters."""
    serial_number = models.CharField(max_length=50, unique=True)
    reference = models.CharField(max_length=100, unique=True)
    subject = models.CharField(max_length=255)
    author = models.CharField(max_length=100)
    received_date = models.DateField(default=timezone.now)
    date_of_letter = models.DateField()
    receiving_officer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='received_letters')
    signed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='signed_incoming_letters')
    signed_at = models.DateField(null=True, blank=True)
    remarks = models.TextField(blank=True)
    scanned_copy = models.FileField(upload_to='incoming_letters/', validators=[validate_pdf], blank=True)
    is_actioned = models.BooleanField(default=False)

    def __str__(self):
        return f"Incoming: {self.subject} ({self.serial_number})"

class OutgoingLetter(models.Model):
    """Model for outgoing letters."""
    serial_number = models.CharField(max_length=50, unique=True)
    reference = models.CharField(max_length=100, unique=True)
    subject = models.CharField(max_length=255)
    recipient = models.CharField(max_length=255)
    sent_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='sent_letters')
    date_sent = models.DateField(default=timezone.now)
    remarks = models.TextField(blank=True)
    scanned_copy = models.FileField(upload_to='outgoing_letters/', validators=[validate_pdf], blank=True)

    def __str__(self):
        return f"Outgoing: {self.subject} ({self.serial_number})"

class Filing(models.Model):
    """Model to represent a physical file or folder."""
    file_reference = models.CharField(max_length=255, unique=True)
    file_name = models.CharField(max_length=255)
    serial_number = models.CharField(max_length=100, unique=True)
    receiving_department = models.CharField(max_length=255)
    receiving_officer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='filings')
    receiving_date = models.DateField(default=timezone.now)
    scanned_copy = models.FileField(upload_to='filings/', validators=[validate_pdf], blank=True)

    def __str__(self):
        return f"Filing: {self.file_name} ({self.file_reference})"

class FilingDocument(models.Model):
    """Model for individual documents within a filing."""
    filing = models.ForeignKey(Filing, on_delete=models.CASCADE, related_name='documents')
    document_name = models.CharField(max_length=255)
    folio_number = models.CharField(max_length=100, blank=True)
    uploaded_file = models.FileField(upload_to='filing_documents/', validators=[validate_pdf_word])
    upload_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Doc: {self.document_name} in {self.filing.file_reference}"

# --- Your Existing ArchivedFile Model ---

class ArchivedFile(models.Model):
    """
    A model to represent a generic archived file, which can be a letter,
    filing document, etc.
    """
    CATEGORY_CHOICES = [
        ('incoming', 'Incoming Letter'),
        ('outgoing', 'Outgoing Letter'),
        ('filing', 'Filing Document'),
    ]
    category = models.CharField(
        max_length=20,
        choices=CATEGORY_CHOICES,
        help_text="The category of the archived file."
    )
    original_name = models.CharField(
        max_length=255,
        help_text="The original name of the file before archiving."
    )
    archived_name = models.CharField(
        max_length=255,
        help_text="The name of the file in the archive storage."
    )
    archived_date = models.DateTimeField(
        auto_now_add=True,
        help_text="The date and time when the file was archived."
    )
    reference = models.CharField(
        max_length=255,
        blank=True,
        help_text="Optional reference number associated with the file."
    )
    subject = models.CharField(
        max_length=255,
        blank=True,
        help_text="Optional subject or title of the file."
    )
    extra_info = models.TextField(
        blank=True,
        help_text="Any extra information or notes about the archived file."
    )
    restored = models.BooleanField(
        default=False,
        help_text="Indicates if the file has been restored from the archive."
    )

    def __str__(self):
        return f"{self.original_name} ({self.get_category_display()})"

    class Meta:
        verbose_name = "Archived File"
        verbose_name_plural = "Archived Files"
        ordering = ['-archived_date']
