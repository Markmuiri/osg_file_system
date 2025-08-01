from django.contrib import admin
from .models import Profile, IncomingLetter, OutgoingLetter, Filing, FilingDocument

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'employee_number')
    search_fields = ('user__username', 'employee_number')
    list_filter = ('role',)

@admin.register(IncomingLetter)
class IncomingLetterAdmin(admin.ModelAdmin):
    list_display = ('subject', 'reference', 'serial_number', 'received_date', 'receiving_officer', 'is_actioned')
    search_fields = ('subject', 'reference', 'serial_number', 'author')
    list_filter = ('received_date', 'receiving_officer', 'is_actioned')
    date_hierarchy = 'received_date'

@admin.register(OutgoingLetter)
class OutgoingLetterAdmin(admin.ModelAdmin):
    list_display = ('subject', 'reference', 'serial_number', 'date_sent', 'recipient', 'sent_by')
    search_fields = ('subject', 'reference', 'serial_number', 'recipient')
    list_filter = ('date_sent', 'sent_by')
    date_hierarchy = 'date_sent'

@admin.register(Filing)
class FilingAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'file_reference', 'serial_number', 'receiving_department', 'receiving_officer', 'receiving_date')
    search_fields = ('file_name', 'file_reference', 'serial_number', 'receiving_department')
    list_filter = ('receiving_department', 'receiving_officer', 'receiving_date')
    date_hierarchy = 'receiving_date'

@admin.register(FilingDocument)
class FilingDocumentAdmin(admin.ModelAdmin):
    list_display = ('document_name', 'filing', 'folio_number', 'uploaded_at')
    search_fields = ('document_name', 'filing__file_reference', 'folio_number')
    list_filter = ('uploaded_at', 'filing')
