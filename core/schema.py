from drf_spectacular.openapi import AutoSchema

class ViewSetTagSchema(AutoSchema):
    def get_tags(self):
        if hasattr(self.view, 'tag_name'):
            return [self.view.tag_name]
        return super().get_tags()
