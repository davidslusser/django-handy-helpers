"""
Description:
    Collection of helpers to assist with permissions on views

How to use:
    Add in your view as a mixin and define groups per method in permission_dict.
    Example:

        class MyView(MethodUserInAnyGroup, View):
            permission_dict = {'POST': ['superusers'],
                               'GET': ['operators'] }
"""

from django.core.exceptions import PermissionDenied
from django.contrib.auth.views import redirect_to_login
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from braces.views import UserPassesTestMixin


class MethodGroupPermissionBase(object):
    """ Base class for method group permissions """
    def dispatch(self, request, *args, **kwargs):
        if not self.has_permission(request, *args, **kwargs):
            if settings.LOGIN_URL and REDIRECT_FIELD_NAME:
                return redirect_to_login(request.get_full_path(),
                                         settings.LOGIN_URL,
                                         REDIRECT_FIELD_NAME
                                         )
            else:
                raise PermissionDenied
        return super(MethodGroupPermissionBase, self).dispatch(request, *args, **kwargs)


class MethodUserInAllGroups(MethodGroupPermissionBase):
    """
    Description:
        Restrict access based on request method and user group; user must be in ALL required groups

    Usage:
        add as mixin to class definition and put the following in your viewset:
            permission_dict = {'POST': ['site_operators', 'site_admins'],
                               'GET': ['site_operators'],
                              }
    """
    def has_permission(self, request, *args, **kwargs):
        if not hasattr(self, 'permission_dict'):
            return False
        permission_dict_mapping = getattr(self, 'permission_dict', {})
        permission_dict = permission_dict_mapping.get(request.method, [])
        if permission_dict is None:
            return False
        return set(permission_dict).issubset([i.name for i in request.user.groups.all()])


class MethodUserInAnyGroup(MethodGroupPermissionBase):
    """
    Description:
        Restrict access based on request method and user group; user can be in ANY required group

    Usage:
        add as mixin to class definition and put the following in your viewset:
            permission_dict = {'POST': ['site_admins'],
                               'GET': ['site_admins', 'site_operators'],
                              }
    """
    def has_permission(self, request, *args, **kwargs):
        if not hasattr(self, 'permission_dict'):
            return False
        permission_dict_mapping = getattr(self, 'permission_dict', {})
        permission_dict = permission_dict_mapping.get(request.method, [])
        return any(group in [i.name for i in request.user.groups.all()] for group in permission_dict)


class InAllGroups(MethodUserInAllGroups):
    """ wrapper class for MethodUserInAllGroups() created to maintain backwards compatibility """
    pass


class InAnyGroup(MethodUserInAnyGroup):
    """ wrapper class for MethodUserInAnyGroup() created to maintain backwards compatibility """
    pass


class UserInAnyGroup(UserPassesTestMixin):
    """
    Description:
        Returns True if user is a member of ANY group (provided by self.permission_group_list)

    Usage:
        add as mixin to class definition and assign permission_group_list like the following:
            permission_group_list = ['my_group_01', 'my_group_02']
    """
    def test_func(self, user):
        user_group_list = [i.name for i in user.groups.all()]
        return any(map(lambda each: each in user_group_list, self.permission_group_list))


class UserInAllGroups(UserPassesTestMixin):
    """
    Description:
        Return True if user is a member of ALL groups (provided by self.permission_group_list)
    Usage:
        add as mixin to class definition and assign permission_group_list like the following:
            permission_group_list = ['my_group_01', 'my_group_02']
    """
    def test_func(self, user):
        user_group_list = [i.name for i in user.groups.all()]
        return set(self.permission_group_list).issubset(user_group_list)
