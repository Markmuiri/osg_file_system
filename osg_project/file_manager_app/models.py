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
    valid_extensions = ['.pdf', '.doc', '.docx']
    if file_extension not in valid_extensions:
        raise ValidationError('Only PDF or Word files (.pdf, .doc, .docx) are allowed.')
    if value.size > 10 * 1024 * 1024:  # 10 MB limit
        raise ValidationError('File size must be under 10MB.')


# --- User Management Models ---

class Profile(models.Model):
    """
    Extends Django's built-in User model with additional profile information.
    """
    ROLE_CHOICES = [
        ('officer', 'Officer'),
        ('superuser', 'Superuser'), # Renamed 'admin' to 'superuser' for clarity with Django's built-in concept
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile',
                                help_text="The associated Django User account.")
    role = models.CharField(
        max_length=10,
        choices=ROLE_CHOICES,
        default='officer', # Default to 'officer' as most users will be officers
        help_text="The role of the user within the system (Officer or Superuser)."
    )
    employee_number = models.CharField(
        max_length=50,
        unique=True,
        help_text="Unique employee identification number."
    )
    profile_picture = models.ImageField(
        upload_to='profile_pics/',
        blank=True,
        null=True,
        help_text="Optional profile picture for the user."
    )

    def __str__(self):
        return f"{self.user.username}'s Profile ({self.get_role_display()})"

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"


# Signal to automatically create or update a Profile when a User is created/saved
@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """
    Creates a Profile for a new User or saves an existing Profile when a User is saved.
    """
    if created:
        Profile.objects.create(user=instance)
    # Ensure profile is created even if it doesn't exist yet (e.g., for existing users before signal was added)
    # or if the user is updated directly in admin without going through profile form.
    instance.profile.save()


# --- Incoming Letters Module ---

class IncomingLetter(models.Model):
    """
    Represents an incoming letter to the Office of the Solicitor General.
    """
    received_date = models.DateField(
        default=timezone.now,
        verbose_name="Date Received",
        help_text="The date the letter was received by the office."
    )
    serial_number = models.CharField(
        max_length=50,
        unique=True, # Assuming serial number should be unique for incoming letters
        verbose_name="Serial No.",
        help_text="Unique serial number assigned upon receipt."
    )
    date_of_letter = models.DateField(
        verbose_name="Date of Letter",
        help_text="The date written on the letter itself."
    )
    reference = models.CharField(
        max_length=100,
        unique=True, # Assuming reference should be unique
        verbose_name="Reference No.",
        help_text="The reference number of the incoming letter."
    )
    subject = models.CharField(
        max_length=255,
        verbose_name="Subject",
        help_text="The subject line of the letter."
    )
    author = models.CharField(
        max_length=100,
        verbose_name="Author/Sender",
        help_text="The name of the person or entity who sent the letter."
    )
    receiving_officer = models.ForeignKey(
        User,
        on_delete=models.SET_NULL, # If user is deleted, set to null
        null=True,
        blank=True, # Allow to be blank initially if assigned later
        related_name='incoming_letters_received',
        verbose_name="Receiving Officer",
        help_text="The officer responsible for handling this letter."
    )
    # Note: 'action_officer_dept' from example is removed as 'receiving_officer' links to User.
    # If a separate 'action department' field is needed, it can be added as a CharField or ForeignKey.
    # For now, assuming receiving_officer implies the department.

    remarks = models.TextField(
        verbose_name="Remarks",
        blank=True,
        help_text="Any additional remarks or notes about the letter."
    )
    scanned_copy = models.FileField(
        upload_to='incoming_letters_scans/',
        verbose_name="Scanned Copy (PDF)",
        blank=True,
        null=True,
        validators=[validate_pdf],
        help_text="Upload a scanned PDF copy of the incoming letter (Max 5MB)."
    )
    # Fields for signing/actioning (from example, good for tracking workflow)
    signed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='incoming_letters_signed',
        help_text="The user who signed off on this letter's action."
    )
    signed_at = models.DateField(
        blank=True,
        null=True,
        help_text="Date the letter was signed off."
    )
    signature = models.ImageField(
        upload_to='signatures/',
        blank=True,
        null=True,
        help_text="Digital signature (if applicable)."
    )
    sender = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Full name or organization of the sender (redundant with author, but kept from example)."
    )
    is_actioned = models.BooleanField(
        default=False,
        help_text="Indicates if the letter has been actioned or processed."
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Incoming: {self.subject} ({self.reference})"

    class Meta:
        verbose_name = "Incoming Letter"
        verbose_name_plural = "Incoming Letters"
        ordering = ['-received_date', '-serial_number']


# --- Outgoing Letters Module ---

class OutgoingLetter(models.Model):
    """
    Represents an outgoing letter from the Office of the Solicitor General.
    """
    date_sent = models.DateField(
        default=timezone.now,
        verbose_name="Date Sent",
        help_text="The date the letter was dispatched."
    )
    serial_number = models.CharField(
        max_length=50,
        unique=True, # Assuming serial number should be unique for outgoing letters
        verbose_name="Serial No.",
        help_text="Unique serial number assigned upon dispatch."
    )
    reference = models.CharField(
        max_length=100,
        unique=True, # Assuming reference should be unique
        verbose_name="Reference No.",
        help_text="The reference number of the outgoing letter."
    )
    subject = models.CharField(
        max_length=255,
        verbose_name="Subject",
        help_text="The subject line of the letter."
    )
    recipient = models.CharField(
        max_length=255,
        verbose_name="Recipient",
        help_text="The name of the person or entity receiving the letter."
    )
    sent_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='outgoing_letters_sent',
        verbose_name="Sent By Officer",
        help_text="The officer who dispatched this letter."
    )
    scanned_copy = models.FileField(
        upload_to='outgoing_letters/',
        blank=True,
        null=True
    )
    receipt_file = models.FileField(
        upload_to='outgoing_receipts/',
        blank=True,
        null=True
    )
    remarks = models.TextField(
        verbose_name="Remarks",
        blank=True,
        help_text="Any additional remarks or notes about the letter."
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Outgoing: {self.subject} ({self.reference})"

    class Meta:
        verbose_name = "Outgoing Letter"
        verbose_name_plural = "Outgoing Letters"
        ordering = ['-date_sent', '-serial_number']


# --- Filings Module ---

class Filing(models.Model):
    """
    Represents a legal filing or case file.
    """
    file_reference = models.CharField(
        max_length=255,
        unique=True, # File reference should be unique
        verbose_name="File Reference",
        help_text="Unique reference number for the filing (e.g., OSG/FIL/2023/001)."
    )
    file_name = models.CharField(
        max_length=255,
        verbose_name="File Name",
        help_text="A descriptive name for the filing (e.g., 'Case of John Doe vs. State')."
    )
    serial_number = models.CharField(
        max_length=100,
        unique=True, # Serial number should be unique
        verbose_name="Serial Number",
        help_text="Unique serial number for the filing."
    )
    receiving_department = models.CharField(
        max_length=255,
        verbose_name="Receiving Department",
        help_text="The department receiving the filing (e.g., Litigation, Advisory)."
    )
    receiving_officer = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='filings_received',
        verbose_name="Receiving Officer",
        help_text="The officer responsible for this filing."
    )
    receiving_date = models.DateField(
        verbose_name="Receiving Date",
        help_text="The date the filing was received."
    )
    # The 'date' field from example is renamed to 'created_at' for clarity
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Date Created",
        help_text="The date and time the filing record was created in the system."
    )
    # This 'scanned_copy' is for a main PDF summary of the filing, if applicable
    scanned_copy = models.FileField(
        upload_to='filings_main_scans/',
        verbose_name="Main Scanned Copy (PDF)",
        blank=True,
        null=True,
        validators=[validate_pdf],
        help_text="Upload a main scanned PDF copy of the filing (Max 5MB)."
    )

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Filing: {self.file_name} ({self.file_reference})"

    class Meta:
        verbose_name = "Filing"
        verbose_name_plural = "Filings"
        ordering = ['-receiving_date', '-created_at']



class FilingDocument(models.Model):
    """
    Represents individual documents associated with a Filing.
    This is where CSV/Excel validation applies.
    """
    filing = models.ForeignKey(
        Filing,
        on_delete=models.CASCADE,
        related_name='documents',
        help_text="The filing this document belongs to."
    )
    document_name = models.CharField(
        max_length=255,
        help_text="A descriptive name for the document (e.g., 'Financial Report', 'Witness List')."
    )
    folio_number = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Optional folio number for the document."
    )
    uploaded_file = models.FileField(
        upload_to='filing_docs/',
        validators=[validate_pdf_word],  # Apply PDF/Word validation here
        help_text="Upload the document (PDF or Word format, Max 10MB)."
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.document_name} ({self.filing.file_reference})"


# --- Archived Files Model ---

class ArchivedFile(models.Model):
    """
    Represents a file that has been archived, either incoming/outgoing letters or filing documents.
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


