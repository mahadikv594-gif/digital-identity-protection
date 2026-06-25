from django.db import models

class ScanHistory(models.Model):
    text = models.TextField()
    risk = models.IntegerField()
    level = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.level} - {self.risk}%"