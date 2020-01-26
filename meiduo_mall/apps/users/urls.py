from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^register/$', views.RegisterView.as_view(), name='register'),
    url(r'^usernames/(?P<username>[a-zA-Z0-9_-]{5,20})/count/', views.UsernameCountView.as_view()),
    url(r'^mobiles/(?P<mobile>1[3-9]\d{9})/count/',views.MobileCountView.as_view()),
    url(r'^login/$', views.LoginView.as_view(),name='login'),
    # 退出  logout/
    url(r'^logout/$', views.LogoutView.as_view(),name='logout'),
    # 用户中心     info
    url(r'^info/$', views.UserInfoView.as_view(),name='info'),
    # 用户中心 -- 新增邮箱emails
    url(r'^emails/$', views.EmailView.as_view()),
    # 用户中心 -- 激活邮箱emails
    url(r'^emails/verification/$', views.EmailVerifyView.as_view()),
    # 收货地址
    url(r'^address/$', views.AddressView.as_view()),
    ####### 忘记密码的子路由
    # 跳转 找回密码页面
    url(r'^find_password/$', views.FindPasswordView.as_view()),
    # 验证用户是否存在
    url(r'^accounts/(?P<username>[a-zA-Z0-9_-]{5,20})/sms/token/$', views.FirstView.as_view()),
    # 发送短信验证码
    url(r'^find_password_sms_codes/(?P<mobile>1[3-9]\d{9})/$', views.FindPasswordSendSmsCodeView.as_view()),
    # 第二步 提交
    url(r'^accounts/(?P<mobile>[a-zA-Z0-9_-]{5,20})/password/token/$', views.SecondView.as_view()),
    # 重置密码+第三步提交
    url(r'^users/(?P<user_id>\d+)/new_password/$', views.UserNewPasswordView.as_view()),

]

