from django.db import models

# Create your models here.

class Education(models.Model):
    doctor = models.ForeignKey("accounts.Account", on_delete=models.CASCADE, related_name='educations')
    institution_name = models.CharField(max_length=200)
    degree = models.CharField(max_length=200)
    field_of_study = models.CharField(max_length=200)
    start_date = models.DateField()
    end_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return f"{self.degree} in {self.field_of_study} from {self.institution_name}"
    
class Certification(models.Model):
    doctor = models.ForeignKey("accounts.Account", on_delete=models.CASCADE, related_name='certifications')
    certificate_name = models.CharField(max_length=200)
    issuing_organization = models.CharField(max_length=200)
    issue_date = models.DateField()
    expiration_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return f"{self.certificate_name} by {self.issuing_organization}"
    
class Specialization(models.Model):
    doctor = models.ForeignKey("accounts.Account", on_delete=models.CASCADE, related_name='specializations')
    area_of_specialization = models.CharField(max_length=200)

    def __str__(self):
        return self.area_of_specialization
    
class DoctorAvailability(models.Model):
    doctor = models.ForeignKey("accounts.Account", on_delete=models.CASCADE, related_name='availabilities')
    day_of_week = models.CharField(max_length=20)
    start_time = models.TimeField()
    end_time = models.TimeField()

    def __str__(self):
        return f"{self.doctor.username} - {self.day_of_week}: {self.start_time} to {self.end_time}"
    