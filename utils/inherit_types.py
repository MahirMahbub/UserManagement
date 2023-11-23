from typing import TypeVar

GenericUser = TypeVar('GenericUser', bound="AbstractUser")
ChildUser = TypeVar('ChildUser', bound="CallableUser")
