from rest_framework import serializers

from users.models import User
from .models import GenericBaseModel


class GenericBaseModelSerializer(serializers.ModelSerializer):
    """
    A generic serializer for the GenericBaseModel.
    It includes fields for created_at, created_by, updated_at, and updated_by.
    """
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)
    updated_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = GenericBaseModel
        fields = '__all__'

    def to_internal_value(self, data):
        """
        Override to_internal_value to handle created_by and updated_by fields.
        These fields are set automatically based on the request user.
        """
        if 'created_by' in data:
            data.pop('created_by')
        if 'updated_by' in data:
            data.pop('updated_by')
        if self.context and 'request' in self.context:
            request = self.context['request']
            if request and getattr(request.user, 'is_authenticated', False):
                data['created_by'] = request.user.id
        return super().to_internal_value(data)

    def create(self, validated_data):
        """
        Override the create method to set created_by fields.
        """
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        """
        Override the update method to set updated_by fields.
        """
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['updated_by'] = request.user
        return super().update(instance, validated_data)