from django.db import models
#from accounts.models import Account

# Create your models here.

class Consultation(models.Model):
    title = models.CharField(max_length=200)
    doctor = models.ForeignKey("accounts.Account", on_delete= models.CASCADE, related_name= 'doctor_consultations')
    patient = models.ForeignKey("accounts.Account", on_delete= models.CASCADE, related_name= 'patient_consultations')
    appointment_date = models.DateTimeField()
    consultation_type = models.CharField(max_length=100)
    status = models.CharField(max_length=50)
    reason_to_visit = models.TextField()
    notes = models.TextField(blank=True, null=True)
    prescriptions = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return self.title