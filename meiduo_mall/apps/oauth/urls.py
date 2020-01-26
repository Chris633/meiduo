from django.conf.urls import url
from . import views

urlpatterns = [

    url(r'^qq/login/$', views.QQAuthURLView.as_view(), name='qqlogin'),
    # qq登陆成功之后的回调地址
    url(r'^oauth_callback/$', views.QQOauthCallbackView.as_view()),

    # 点击微博登录的路由
    url(r'^sina/login/$', views.WeiboLoginView.as_view()),
    # 微博回调的路由
    url(r'^sina_callback/$', views.WeiboCallbackView.as_view()),
    # 微博绑定用户 oauth/sina/user/
    url(r'^oauth/sina/user/$', views.WeiboBindUserView.as_view()),
]
