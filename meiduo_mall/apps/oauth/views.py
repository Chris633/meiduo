import json

from django import http
from django.conf import settings
from django.contrib.auth import login
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View
from QQLoginTool.QQtool import OAuthQQ

from apps.oauth.models import OAuthQQUser, OAuthSinaUser
from apps.oauth.sinaweibopy3 import APIClient
from apps.users.models import User
from utils.response_code import RETCODE
from utils.secret import SecretOauth


def is_bind_openid(openid,request):
    # 去数据库查询有没有openid
    try:
        oauth_user = OAuthQQUser.objects.get(openid=openid)
    except Exception as e:
        # 如果openid没绑定美多商城用户 --> 跳转绑定页面
        from utils.secret import SecretOauth
        openid = SecretOauth().dumps({'openid': openid})
        return render(request, 'oauth_callback.html', context={'openid': openid})
    else:
        # 如果openid已绑定美多商城用户 --> 跳转首页
        user = oauth_user.user
        login(request, user)

        # 重定向到主页
        response = redirect(reverse('contents:index'))

        # 登录时用户名写入到cookie，有效期30天
        response.set_cookie('username', user.username, max_age=3600 * 24 * 30)

        return response


class QQOauthCallbackView(View):
    def get(self,request):
        code = request.GET.get('code')
        if not code:
            return http.HttpResponseForbidden('code无效了')
        # 实例化QQ认证对象
        oauth = OAuthQQ(client_id=settings.QQ_CLIENT_ID,
                        client_secret=settings.QQ_CLIENT_SECRET,
                        redirect_uri=settings.QQ_REDIRECT_URI,
                        state=None)
        # code --> token
        token = oauth.get_access_token(code)
        # token --> openid
        openid = oauth.get_open_id(token)

        # 判断是否绑定openid
        response = is_bind_openid(openid,request)

        return response

    def post(self,request):
        # 1.解析参数
        mobile = request.POST.get('mobile')
        pwd = request.POST.get('password')
        sms_code = request.POST.get('sms_code')
        openid = request.POST.get('openid')

        if openid is None:
            return http.HttpResponseForbidden('openid失效了')
        from utils.secret import SecretOauth
        openid = SecretOauth().loads(openid).get('openid')

        
        # 2.校验  判空 正则 图形 短信验证码

        # 3.校验mobile是否存在
        try:
            user = User.objects.get(mobile=mobile)
            if not user.check_password(pwd):
                return render(request,'oauth_callback.html', {'errmsg':"用户名或密码不正确"})
        except Exception as e:
            user = User.objects.create_user(username=mobile, password=pwd, mobile=mobile)
        # 4.绑定openid
        oauth_user = OAuthQQUser.objects.create(openid=openid, user=user)
        # 5.保持登陆状态 set_cookie 重定向到首页
        login(request, oauth_user.user)
        response = redirect(reverse('contents:index'))
        response.set_cookie('username', user.username, max_age=24*30*3600)
        return response


class QQAuthURLView(View):
    # 获取qq登陆网址
    def get(self,request):
        # 实例化QQ认证对象
        oauth = OAuthQQ(client_id=settings.QQ_CLIENT_ID,
                        client_secret=settings.QQ_CLIENT_SECRET,
                        redirect_uri=settings.QQ_REDIRECT_URI,
                        state=None)
        # 获取login
        login_url = oauth.get_qq_url()
        # 返回
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'login_url':login_url})


class WeiboBindUserView(View):
    def post(self,request):

        json_dict = json.loads(request.body.decode())

        mobile = json_dict.get('mobile')
        pwd = json_dict.get('password')
        sms_code = json_dict.get('sms_code')
        # 解密
        uid = SecretOauth().loads(json_dict.get('uid')).get('uid')

        if not uid:
            return  http.JsonResponse({'status':5004,'errmsg':'无效的uid'})

        from django_redis import get_redis_connection
        redis_code_client = get_redis_connection('sms_code')
        redis_code = redis_code_client.get("sms_%s" % mobile)

        if redis_code is None:
            return  http.JsonResponse({'status':5001,'errmsg':'无效的短信验证码'})

        if sms_code != redis_code.decode():
            return http.JsonResponse({'status':5002,'errmsg':'输入短信验证码有误'})


        # 保存注册数据
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 用户不存在,新建用户
            user = User.objects.create_user(username=mobile, password=pwd, mobile=mobile)
        else:
            # 如果用户存在，检查用户密码
            if not user.check_password(pwd):
                return http.JsonResponse({'status':5002,'errmsg':'用户名或密码错误'})

        # 绑定用户
        OAuthSinaUser.objects.create(
            uid=uid,
            user=user
        )

        # 保持登录状态
        login(request, user)
        response = http.JsonResponse({'status':5000,'errmsg':'绑定成功!'})
        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)

        return response


class WeiboCallbackView(View):
    def get(self, request):
        client = APIClient(
            # app_key： app_key值
            app_key=settings.APP_KEY,
            # app_secret：app_secret 值
            app_secret=settings.APP_SECRET,
            # redirect_uri ： 回调地址
            redirect_uri=settings.REDIRECT_URL
        )

        # 1.获取回调传回来的 code
        code = request.GET.get('code')

        # 2.根据code值获取access_token和uid值
        result = client.request_access_token(code)
        access_token = result.access_token
        uid = result.uid

        # 3.判断 美多后台是否绑定了 uid; 如果绑定跳转到首页--没有绑定跳转到绑定页面(sina_callback.html)
        try:
            sina_user = OAuthSinaUser.objects.get(uid=uid)

        except OAuthSinaUser.DoesNotExist:
            # 不存在--绑定页面(sina_callback.html)--带着uid
            uid = SecretOauth().dumps({'uid': uid})
            return render(request, 'sina_callback.html', context={'uid': uid})

        user = sina_user.user

        # 保持登录状态
        login(request, user)

        # 设置首页用户名
        response = redirect(reverse('contents:index'))
        response.set_cookie('username', user.username, max_age=24 * 14 * 3600)
        # 重定向 首页

        return response


class WeiboLoginView(View):
    def get(self, request):
        client = APIClient(
            # app_key： app_key值
            app_key=settings.APP_KEY,
            # app_secret：app_secret 值
            app_secret=settings.APP_SECRET,
            # redirect_uri ： 回调地址
            redirect_uri=settings.REDIRECT_URL
        )

        login_url = client.get_authorize_url()

        return http.JsonResponse({'code': 0, 'errmsg': '微博登录网址', "login_url": login_url})
