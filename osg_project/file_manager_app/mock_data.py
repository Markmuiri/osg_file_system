# Save this code in a file, e.g., mock_data.py, and run it in the Django shell.
# python manage.py shell < mock_data.py

from osg_project.file_manager_app.models import IncomingLetter, OutgoingLetter, Filing
from django.contrib.auth.models import User
from django.utils import timezone
from faker import Faker
import random
import datetime
import uuid

# Initialize Faker to generate realistic data
fake = Faker()

def create_mock_data(num_records=100):
    """
    Generates a specified number of mock data records for IncomingLetter,
    OutgoingLetter, and Filing models.

    Args:
        num_records (int): The number of records to create for each model.
    """
    print(f"Starting to create {num_records} mock records for each model...")

    # --- Pre-requisite: Fetch a User to link records to ---
    # The script requires at least one user to exist in the database.
    # If no users exist, uncomment the lines below to create a dummy user.
    # try:
    #     officer = User.objects.get(username='testuser')
    # except User.DoesNotExist:
    #     officer = User.objects.create_user(username='testuser', password='password123')
    #     print("Created a dummy user 'testuser' to link records.")

    try:
        officer = User.objects.first()
        if not officer:
            print("No users found. Please create a user first or uncomment the dummy user creation code.")
            return
    except Exception as e:
        print(f"Error fetching user: {e}")
        return

    print(f"Using user '{officer.username}' to link mock data.")

    # --- Generate IncomingLetter Data ---
    print("\nGenerating Incoming Letters...")
    for i in range(num_records):
        date_of_letter = fake.date_time_between(start_date='-2y', end_date='now', tzinfo=datetime.timezone.utc)
        IncomingLetter.objects.create(
            reference=fake.unique.bothify(text='IN-????-#####'),
            subject=fake.sentence(nb_words=6),
            author=fake.company(),
            date_of_letter=date_of_letter,
            received_date=fake.date_time_between(start_date=date_of_letter, end_date='now', tzinfo=datetime.timezone.utc),
            receiving_officer=officer,
            serial_number=f"IN-SN-{i:05d}-{uuid.uuid4().hex[:6]}",  # <-- Ensures uniqueness even across runs
            # scanned_copy is a file field, so we omit it for mock data.
        )
    print(f"{num_records} Incoming Letters created successfully.")

    # --- Generate OutgoingLetter Data ---
    print("\nGenerating Outgoing Letters...")
    for i in range(num_records):
        OutgoingLetter.objects.create(
            reference=fake.unique.bothify(text='OUT-????-#####'),
            subject=fake.sentence(nb_words=6),
            recipient=fake.company(),
            date_sent=fake.date_time_between(start_date='-2y', end_date='now', tzinfo=datetime.timezone.utc),
            sent_by=officer,  # <-- Use the correct field name from your model
            serial_number=f"OUT-SN-{i:05d}",  # <-- Ensures uniqueness for OutgoingLetter (if field exists)
            # body_text=fake.text(), # Uncomment if your model has this field
            # scanned_copy is a file field, so we omit it for mock data.
        )
    print(f"{num_records} Outgoing Letters created successfully.")

    # --- Generate Filing Data ---
    print("\nGenerating Filings...")
    departments = ['Legal', 'Finance', 'HR', 'Admin', 'Operations', 'IT', 'Procurement', 'Marketing', 'Logistics']
    for i in range(num_records):
        Filing.objects.create(
            file_reference=fake.unique.bothify(text='FIL-####-??'),
            file_name=fake.catch_phrase(),
            serial_number=f"FIL-SN-{i:05d}",  # <-- Ensures uniqueness for Filing
            receiving_department=random.choice(departments),
            receiving_officer=officer,
            receiving_date=fake.date_time_between(start_date='-2y', end_date='now', tzinfo=datetime.timezone.utc),
            # scanned_copy is a file field, so we omit it for mock data.
        )
    print(f"{num_records} Filings created successfully.")
    
    print("\nAll mock data generation complete.")

# To run this script, simply save it and execute from your Django project root:
# python manage.py shell < your_script_name.py
# Or copy and paste the code line-by-line into the shell after running:
# python manage.py shell
# >>> from file_manager_app import models
# >>> ... [paste the function and call it]
create_mock_data()
