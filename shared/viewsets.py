import datetime
from contextlib import nullcontext

from rest_framework import viewsets, mixins, status, filters
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.pagination import PageNumberPagination


class SoftDeleteModelMixin:
    """
    Destroy a model instance.
    """

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.is_hidden = True
        instance.deleted_by = self.request.user
        instance.deleted_at = datetime.datetime.now()
        instance.save(update_fields=['is_hidden', 'deleted_by', 'deleted_at'])


class PaginatedListMixin:
    """
    Mixin to provide pagination for list views.
    """
    pagination_class = None  # Set this to your pagination class if needed

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return Response({
                'page': self.paginator.page.number if hasattr(self, 'paginator') and hasattr(self.paginator,
                                                                                             'page') else 1,
                'records': len(serializer.data),
                'total': self.paginator.page.paginator.count if hasattr(self, 'paginator') and hasattr(self.paginator,
                                                                                                       'page') else len(
                    queryset),
                'rows': serializer.data
            })

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'page': 1,
            'records': len(serializer.data),
            'total': len(queryset),
            'rows': serializer.data
        })


class DetailedRetrieveMixin:
    """
    Mixin to provide detailed retrieve functionality.
    """

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        queryset = self.filter_queryset(self.get_queryset()).order_by('pk')
        pk_list = list(queryset.values_list('pk', flat=True))
        try:
            idx = pk_list.index(instance.pk)
        except ValueError:
            idx = -1
        prev_pk = pk_list[idx - 1] if idx > 0 else None
        next_pk = pk_list[idx + 1] if idx != -1 and idx + 1 < len(pk_list) else None
        serializer = self.get_serializer(instance)
        return Response({
            'data': serializer.data,
            'prev_pk': prev_pk,
            'next_pk': next_pk,
            'total': len(pk_list)
        })


class PaginatedActiveListMixin:
    """
    Mixin to provide pagination for list views for active instances.
    """
    pagination_class = None  # Set this to your pagination class if needed

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset().filter(is_hidden=False))
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return Response({
                'page': self.paginator.page.number if hasattr(self, 'paginator') and hasattr(self.paginator,
                                                                                             'page') else 1,
                'records': len(serializer.data),
                'total': self.paginator.page.paginator.count if hasattr(self, 'paginator') and hasattr(self.paginator,
                                                                                                       'page') else len(
                    queryset),
                'rows': serializer.data
            })

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'page': 1,
            'records': len(serializer.data),
            'total': len(queryset),
            'rows': serializer.data
        })


class DetailedActiveRetrieveMixin:
    """
    Mixin to provide detailed retrieve functionality for active instances.
    """

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.is_hidden:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        queryset = self.filter_queryset(self.get_queryset().filter(is_hidden=False)).order_by('pk')
        pk_list = list(queryset.values_list('pk', flat=True))
        try:
            idx = pk_list.index(instance.pk)
        except ValueError:
            idx = -1
        prev_pk = pk_list[idx - 1] if idx > 0 else None
        next_pk = pk_list[idx + 1] if idx != -1 and idx + 1 < len(pk_list) else None
        serializer = self.get_serializer(instance)
        return Response({
            'data': serializer.data,
            'prev_pk': prev_pk,
            'next_pk': next_pk,
            'total': len(pk_list)
        })


class PaginatedHiddenListMixin:
    """
       Mixin to provide pagination for hidden list views.
    """
    pagination_class = None  # Set this to your pagination class if needed

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset().filter(is_hidden=True))
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return Response({
                'page': self.paginator.page.number if hasattr(self, 'paginator') and hasattr(self.paginator,
                                                                                             'page') else 1,
                'records': len(serializer.data),
                'total': self.paginator.page.paginator.count if hasattr(self, 'paginator') and hasattr(self.paginator,
                                                                                                       'page') else len(
                    queryset),
                'rows': serializer.data
            })

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'page': 1,
            'records': len(serializer.data),
            'total': len(queryset),
            'rows': serializer.data
        })


class DetailedHiddenRetrieveMixin:
    """
    Mixin to provide detailed retrieve functionality.
    """

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance.is_hidden:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        queryset = self.filter_queryset(self.get_queryset().filter(is_hidden=True)).order_by('pk')
        pk_list = list(queryset.values_list('pk', flat=True))
        try:
            idx = pk_list.index(instance.pk)
        except ValueError:
            idx = -1
        prev_pk = pk_list[idx - 1] if idx > 0 else None
        next_pk = pk_list[idx + 1] if idx != -1 and idx + 1 < len(pk_list) else None
        serializer = self.get_serializer(instance)
        return Response({
            'data': serializer.data,
            'prev_pk': prev_pk,
            'next_pk': next_pk,
            'total': len(pk_list)
        })


class CreateWithUserMixin(mixins.CreateModelMixin):

    def perform_create(self, serializer):
        user = self.request.user
        serializer.save(created_by=user)


class UpdateWithUserMixin(mixins.UpdateModelMixin):

    def perform_update(self, serializer):
        user = self.request.user
        serializer.save(
            updated_by=user,
            updated_at=datetime.datetime.now()
        )



class GenericModelViewSet(
    SoftDeleteModelMixin,
    PaginatedActiveListMixin,
    DetailedActiveRetrieveMixin,
    CreateWithUserMixin,
    UpdateWithUserMixin,
    viewsets.GenericViewSet
):
    """
    A generic viewset that provides default implementations for list, retrieve, update, and soft-delete actions.
    """
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    permission_classes = []
    lookup_field = 'pk'
    queryset = None
    serializer_class = None
    filterset_fields = []
    search_fields = []
    ordering_fields = []
    ordering = ['-created_at']

    def get_queryset(self):
        return self.queryset.filter(is_hidden=False)

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset().filter(is_hidden=False))
        filter_kwargs = {self.lookup_field: self.kwargs[self.lookup_field]}
        obj = get_object_or_404(queryset, **filter_kwargs)
        self.check_object_permissions(self.request, obj)
        return obj
