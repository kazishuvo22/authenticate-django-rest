from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token

from authenticate import views

from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register('users', views.UserViewSet, basename='user-list')
# router.register('login', views.LoginView, basename='login')

urlpatterns = [
    path('', include(router.urls)),
    path('account/logout/', views.LogoutView.as_view(), name='logout'),
    path('login/', views.login_user, name='login'),
    path('register/', views.Register_Users, name='register'),
]
