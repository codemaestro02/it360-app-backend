# create a custom router for the core app
from rest_framework.routers import DefaultRouter

class CoreRouter(DefaultRouter):
    """
    Custom router for the core app.
    This router can be extended to include additional functionality or custom behavior.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag_name = ""

    def register(self, prefix, viewset, basename=None, **kwargs):
        """
        Register a viewset with the router.
        This method can be overridden to add custom behavior when registering viewsets.
        """
        if hasattr(viewset, 'tag_name'):
            self.tag_name = viewset.tag_name
        super().register(prefix, viewset, basename)

    # def get_default_basename(self, viewset):
    #     """
    #     Override the default basename generation to include the tag if available.
    #     """
    #     if hasattr(viewset, 'tag') and viewset.tag:
    #         return f"{viewset.tag}-{viewset.__name__}"
    #     return getattr(viewset, 'basename', None) or getattr(getattr(viewset, 'queryset', None), 'model', type(viewset)).__name__.lower()



# Example usage of the custom router
# router = CoreRouter()
# router.register(r'some-endpoint', SomeViewSet, basename='some-endpoint')
# urlpatterns = [
#     path('', include(router.urls)),
# ]