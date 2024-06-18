# coding: utf-8

"""
    zrok

    zrok client access  # noqa: E501

    OpenAPI spec version: 0.3.0
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""

import pprint
import re  # noqa: F401

import six

class CreateFrontendRequest(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """
    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'z_id': 'str',
        'url_template': 'str',
        'public_name': 'str',
        'permission_mode': 'str'
    }

    attribute_map = {
        'z_id': 'zId',
        'url_template': 'url_template',
        'public_name': 'public_name',
        'permission_mode': 'permissionMode'
    }

    def __init__(self, z_id=None, url_template=None, public_name=None, permission_mode=None):  # noqa: E501
        """CreateFrontendRequest - a model defined in Swagger"""  # noqa: E501
        self._z_id = None
        self._url_template = None
        self._public_name = None
        self._permission_mode = None
        self.discriminator = None
        if z_id is not None:
            self.z_id = z_id
        if url_template is not None:
            self.url_template = url_template
        if public_name is not None:
            self.public_name = public_name
        if permission_mode is not None:
            self.permission_mode = permission_mode

    @property
    def z_id(self):
        """Gets the z_id of this CreateFrontendRequest.  # noqa: E501


        :return: The z_id of this CreateFrontendRequest.  # noqa: E501
        :rtype: str
        """
        return self._z_id

    @z_id.setter
    def z_id(self, z_id):
        """Sets the z_id of this CreateFrontendRequest.


        :param z_id: The z_id of this CreateFrontendRequest.  # noqa: E501
        :type: str
        """

        self._z_id = z_id

    @property
    def url_template(self):
        """Gets the url_template of this CreateFrontendRequest.  # noqa: E501


        :return: The url_template of this CreateFrontendRequest.  # noqa: E501
        :rtype: str
        """
        return self._url_template

    @url_template.setter
    def url_template(self, url_template):
        """Sets the url_template of this CreateFrontendRequest.


        :param url_template: The url_template of this CreateFrontendRequest.  # noqa: E501
        :type: str
        """

        self._url_template = url_template

    @property
    def public_name(self):
        """Gets the public_name of this CreateFrontendRequest.  # noqa: E501


        :return: The public_name of this CreateFrontendRequest.  # noqa: E501
        :rtype: str
        """
        return self._public_name

    @public_name.setter
    def public_name(self, public_name):
        """Sets the public_name of this CreateFrontendRequest.


        :param public_name: The public_name of this CreateFrontendRequest.  # noqa: E501
        :type: str
        """

        self._public_name = public_name

    @property
    def permission_mode(self):
        """Gets the permission_mode of this CreateFrontendRequest.  # noqa: E501


        :return: The permission_mode of this CreateFrontendRequest.  # noqa: E501
        :rtype: str
        """
        return self._permission_mode

    @permission_mode.setter
    def permission_mode(self, permission_mode):
        """Sets the permission_mode of this CreateFrontendRequest.


        :param permission_mode: The permission_mode of this CreateFrontendRequest.  # noqa: E501
        :type: str
        """
        allowed_values = ["open", "closed"]  # noqa: E501
        if permission_mode not in allowed_values:
            raise ValueError(
                "Invalid value for `permission_mode` ({0}), must be one of {1}"  # noqa: E501
                .format(permission_mode, allowed_values)
            )

        self._permission_mode = permission_mode

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(CreateFrontendRequest, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, CreateFrontendRequest):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
