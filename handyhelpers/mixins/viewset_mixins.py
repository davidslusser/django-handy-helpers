from rest_framework import status
from rest_framework_filters.filters import RelatedFilter
from django.http import JsonResponse
from django.conf import settings


class InvalidLookupMixin:
    """ A mixin for Django Rest Framework viewsets to check query parameters and return an error if any query parameter
    is not a included in defined in a filter_class (typically defined in your filterset), and element of
    filter_fields (typically set in your viewset), or a valid model field.
    Order of precedence is: filter_class, filterset_fields, filter_fields, model field.

    class parameters:
        request       - request object (as provided by Viewset)
        model         - django model (as provided by Viewset)
        queryset      - django queryset (as provided by Viewset)
        filter_class  - optional filter_class (as provided by Viewset)
        filter_fields - optional filter_fields (as provided by Viewset)

    example usage:
        class MyModelViewSet(InvalidLookupMixin, viewsets.ReadOnlyModelViewSet):
    """
    request = None
    model = None
    queryset = None
    filter_class = None
    filterset_fields = []
    filter_fields = []

    def get_lookup_expression(self, fs_filter, related_field=None, lookup_expression_list=None):
        """
        get lookup expressions as defined in a FilterSet filter

        Args:
            fs_filter:              list of filters as defined in the filterset
            related_field:          related field as defined in filterset
            lookup_expression_list: list of lookup expressions as defined for a field in a filterset

        Returns:
            list of filtered lookup expressions
        """
        if not lookup_expression_list:
            lookup_expression_list = []
        for i, j in fs_filter.items():
            # protect agains recursion if field relates to itself
            if i == related_field:
                continue
            if isinstance(j, RelatedFilter):
                self.get_lookup_expression(j.filterset.get_filters(), related_field=i,
                                           lookup_expression_list=lookup_expression_list)
            else:
                if related_field:
                    expression = '{}__{}'.format(related_field, i)
                    if expression not in lookup_expression_list:
                        lookup_expression_list.append(expression)
                else:
                    if i not in lookup_expression_list:
                        lookup_expression_list.append(i)
        return lookup_expression_list

    def dispatch(self, request, *args, **kwargs):
        for field, val in self.request.GET.dict().items():
            # ignore the '!' in 'field!=value' if filters are used
            field = field.rstrip('!')
            if field in getattr(settings, 'INVALID_LOOKUP_SKIP_LIST',
                                ['offset', 'limit', 'format', 'fields', 'omit', 'expand']):
                continue
            if self.filter_class:
                # if filter_class is available, return error if any query parameter is not a lookup expression
                valid_fields = self.get_lookup_expression(self.filter_class.get_filters())
                if field not in valid_fields:
                    return JsonResponse(data={'detail': '{} is not a valid filter field:'},
                                        status=status.HTTP_404_NOT_FOUND)

            elif self.filterset_fields:
                # if filterset_fields are available, return error if any query parameter is not a filter field
                if field not in self.filterset_fields:
                    return JsonResponse(data={'detail': f'{field} is not valid field. Filterable fields are: '
                                                        f'{self.filterset_fields}'},
                                        status=status.HTTP_404_NOT_FOUND)

            elif self.filter_fields:
                # if filter_fields are available, return error if any query parameter is not an available filter field
                if field not in self.filter_fields:
                    return JsonResponse(data={'detail': f'{field} is not valid field. Filterable fields are: '
                                                        f'{self.filter_fields}'},
                                        status=status.HTTP_404_NOT_FOUND)

            else:
                # if neither filter_class nor filterset_fields are available, return error if any query parameter is
                # not a field in the model
                if field.split('__')[0] not in [i.name for i in self.model._meta.fields +
                                                                self.model._meta.many_to_many]:
                    return JsonResponse(data={'detail': '{} is not a valid field in {}'
                                        .format(field, self.model.__name__)}, status=status.HTTP_404_NOT_FOUND)

        return super().dispatch(request, *args, **kwargs)
