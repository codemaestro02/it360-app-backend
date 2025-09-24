from rest_framework import serializers

from users.models import User
from users.serializers import UserSerializer

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
    created_by_details = UserSerializer(read_only=True, source='created_by')
    updated_by_details = UserSerializer(read_only=True, source='updated_by')
    deleted_by = serializers.PrimaryKeyRelatedField(read_only=True)
    deleted_at = serializers.DateTimeField(read_only=True)
    deleted_by_details = UserSerializer(read_only=True, source='deleted_by')
    is_hidden = serializers.BooleanField(
        required=False, allow_null=True, default=False
    )


    class Meta:
        fields = [
            'created_at', 'created_by', 'created_by_details',
            'updated_at', 'updated_by', 'updated_by_details',
            'deleted_at', 'deleted_by', 'deleted_by_details',
            'is_hidden'
        ]