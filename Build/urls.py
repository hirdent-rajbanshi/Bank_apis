from django.urls import path
from . import views

urlpatterns = [
    path('signup', views.signup),
    path('login', views.login),
    path('deposit', views.deposit),
    path('withdraw', views.withdraw),
    path('balance', views.balance),
]
