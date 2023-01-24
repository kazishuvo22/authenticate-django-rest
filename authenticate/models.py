from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.contrib.auth.models import AbstractUser, Group


class MyAccountManager(BaseUserManager):
    def create_user(self, email, fullname=None, birthday=None, zipcode=None, password=None
                    ):
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            name=self.normalize_email(email),
            Date_of_Birth=birthday,
            zipcode=zipcode,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        user = self.create_user(
            email=self.normalize_email(email),
            password=password,
        )
        user.is_admin = True
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)


class User(AbstractBaseUser):
    email = models.EmailField(verbose_name="email", max_length=60, unique=True, blank=True, null=True,
                                      default=None)
    Date_of_Birth = models.CharField(max_length=30, blank=True, null=True, default=None)
    name = models.CharField(max_length=30, blank=True, null=True)
    username = models.CharField(max_length=30, unique=True, blank=True, null=True)
    zipcode = models.CharField(max_length=30, blank=True, null=True)
    groups = models.ForeignKey(Group, on_delete=models.CASCADE)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_teacher = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_super_teacher = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'

    objects = MyAccountManager()

    class Meta:
        db_table = "users"

    def __str__(self):
        return str(self.email)

    def has_perm(self, perm, obj=None): return self.is_superuser

    def has_module_perms(self, app_label): return self.is_superuser

# class User(AbstractUser):
#     groups = models.ForeignKey(Group, on_delete=models.CASCADE)
#     email = models.EmailField(max_length=50, unique=True)
#
#     REQUIRED_FIELDS = ['groups_id', 'email']
#
#     class Meta:
#         verbose_name = 'user'
#         verbose_name_plural = 'users'
#
#     def get_full_name(self):
#         return '%s %s' % (self.first_name, self.last_name)
#
#     def get_short_name(self):
#         return self.first_name
#
#     def __str__(self):
#         return self.username
