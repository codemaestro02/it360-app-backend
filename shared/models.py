from django.db import models


class GenericBaseModel(models.Model):
    """
    A generic base model that includes common fields for all models.
    """
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        'users.User', on_delete=models.SET_NULL, null=True, related_name='%(class)s_created'
    )
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        'users.User', on_delete=models.SET_NULL, null=True, related_name='%(class)s_updated'
    )

    class Meta:
        abstract = True
        ordering = ['-created_at']  # Default ordering by creation time