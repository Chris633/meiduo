import base64
import json
import os
import re
from django import http
from django.contrib.auth import login, logout
from django.http import HttpResponseForbidden
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View
from pymysql import DatabaseError
from apps.users.models import User
from apps.users.utils import generate_verify_emails_url
from meiduo_mall.settings.dev import logger
from utils.response_code import RETCODE
from django_redis import get_redis_connection

from django.contrib.auth.mixins import LoginRequiredMixin

from utils.secret import SecretOauth

class AddressView(LoginRequiredMixin, View):
    """用户收货地址"""

    def get(self, request):
        """提供收货地址界面"""
        return render(request, 'user_center_site.html')

class EmailVerifyView(LoginRequiredMixin, View):
    def get(self, request):
        # 1.接收token- 查询参数--request.GET
        token = request.GET.get('token')

        if not token:
            return http.HttpResponseForbidden('token无效了!')
        # 2.解密
        token_dict = SecretOauth().loads(token)

        # 3.校验 user_id  email
        try:
            user = User.objects.get(id=token_dict['user_id'], email=token_dict['email'])
            # 4.激活 email_active = True
            user.email_active = True
            user.save()
        except Exception as e:
            return http.HttpResponseForbidden('token有误!')


        # 5.重定向到 用户中心页面
        return redirect(reverse('users:info'))

class EmailView(LoginRequiredMixin, View):
    """添加邮箱"""

    def put(self, request):
        """实现添加邮箱逻辑"""
        # 接收参数
        json_str = request.body.decode()
        json_dict = json.loads(json_str)
        email = json_dict.get('email')

        # 校验参数
        if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return http.HttpResponseForbidden('参数email有误')

        # 赋值email字段
        try:
            request.user.email = email
            request.user.save()
            # 保存邮箱成功之后  发送邮件---网易发送---耗时任务
            verify_url = generate_verify_emails_url(request.user)
            from celery_tasks.email.tasks import send_verify_email
            send_verify_email.delay(email,verify_url)

        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '添加邮箱失败'})

        # 响应添加邮箱结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '添加邮箱成功'})


class UserInfoView(LoginRequiredMixin, View):
    """用户中心"""

    def get(self, request):
        """提供个人信息界面"""
        context = {
            'username': request.user.username,
            'mobile': request.user.mobile,
            'email': request.user.email,
            'email_active': request.user.email_active
        }
        return render(request, 'user_center_info.html', context=context)


class LogoutView(View):
    """退出登录"""

    def get(self, request):
        """实现退出登录逻辑"""
        # 清理session
        logout(request)
        # 退出登录，重定向到登录页
        response = redirect(reverse('contents:index'))
        # 退出登录时清除cookie中的username
        response.delete_cookie('username')

        return response


class LoginView(View):
    """用户名登录"""

    def get(self, request):
        """
        提供登录界面
        :param request: 请求对象
        :return: 登录界面
        """
        return render(request, 'login.html')

    def post(self, request):
        """
        实现登录逻辑
        :param request: 请求对象
        :return: 登录结果
        """
        # 1.接收三个参数
        username = request.POST.get('username')
        password = request.POST.get('password')
        remembered = request.POST.get('remembered')

        # 2.校验参数
        if not all([username, password]):
            return HttpResponseForbidden('参数不齐全')
        # 2.1 用户名
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return HttpResponseForbidden('请输入5-20个字符的用户名')
        # 2.2 密码
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseForbidden('请输入8-20位的密码')

        # 3.验证用户名和密码--django自带的认证
        from django.contrib.auth import authenticate, login
        user = authenticate(username=username, password=password)

        if user is None:
            return render(request, 'login.html', {'account_errmsg': '用户名或密码错误'})

        # 4.保持登录状态
        login(request, user)

        # 5.是否记住用户名
        if remembered != 'on':
            # 不记住用户名, 浏览器结束会话就过期
            request.session.set_expiry(0)
        else:
            # 记住用户名, 浏览器会话保持两周
            request.session.set_expiry(None)
        # 设置cookie --username--方便其他前端页面去cookie取值
        next = request.GET.get('next')
        if next:
            response = redirect(next)
        else:
            response = redirect(reverse('contents:index'))
        # response.set_cookie('username', username, max_age=24 * 3600 * 15)
        response.set_cookie('username', user.username, max_age=24 * 3600 * 15)

        # 5.重定向到首页
        return response


class MobileCountView(View):
    """判断手机号是否重复注册"""

    def get(self, request, mobile):

        count = User.objects.filter(mobile=mobile).count()

        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '手机号重复', 'count': count})


class UsernameCountView(View):
    """判断用户名是否重复注册"""

    def get(self, request, username):

        count = User.objects.filter(username=username).count()

        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '用户名重复', 'count': count})


class RegisterView(View):
    """用户注册"""

    def get(self, request):
        """
        提供注册界面
        :param request: 请求对象
        :return: 注册界面
        """
        return render(request, 'register.html')

    # def post(self,request):
    #
    #     print("触发 断点")
    #
    #     return render(request, 'register.html')
    def post(self,request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        mobile = request.POST.get('mobile')
        allow = request.POST.get('allow')
        # 判断参数是否齐全
        if not all([username, password, password2, mobile, allow]):
            return http.HttpResponseForbidden('缺少必传参数')
        # 判断用户名是否是5-20个字符
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('请输入5-20个字符的用户名')
        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # 判断两次密码是否一致
        if password != password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')
        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('请输入正确的手机号码')
        # 判断是否勾选用户协议
        if allow != 'on':
            return http.HttpResponseForbidden('请勾选用户协议')
        # try:
        #     User.objects.create_user(username=username, password=password, mobile=mobile)
        # except DatabaseError:
        #     return render(request, 'register.html', {'register_errmsg': '用户名 或 密码错误 '})
        # 完善补充 校验 短信验证码
        sms_code = request.POST.get('msg_code')
        redis_code_client = get_redis_connection('sms_code')
        redis_code = redis_code_client.get("sms_%s" % mobile)
        if redis_code is None:
            return render(request, 'register.html', {'sms_code_errmsg': '无效的短信验证码'})

        if sms_code != redis_code.decode():
            return render(request, 'register.html', {'sms_code_errmsg': '输入短信验证码有误'})

        try:
            user = User.objects.create_user(username=username, password=password, mobile=mobile)
        except Exception as e:
            logger.error(e)
            return render(request, 'register.html', {'register_errmsg': '注册失败'})

        login(request, user)

        return redirect(reverse('contents:index'))
        # return http.HttpResponse('注册成功，重定向到首页')

'''忘记密码视图函数'''
# 跳转 找回密码页面
class FindPasswordView(View):
    def get(self, request):
        return render(request, 'find_password.html')


# 生成 随机码
def generat_csrf():
    return bytes.decode(base64.b64encode(os.urandom(48)))

# 验证用户是否存在
class FirstView(View):
    def get(self, request, username):
        # 1.接收参数
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('image_code_id')

        # 2.校验用户名 和 图形验证码
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return http.JsonResponse({'status': 5004})
        img_client = get_redis_connection('verify_image_code')
        redis_img_code = img_client.get('img_%s' % uuid)

        if image_code.lower() != redis_img_code.decode().lower():
            return http.JsonResponse({'status': 5001})

        # 生成随机64位码字符串 存入redis 为下次发短信提交做准备
        mobile = user.mobile
        random_str = generat_csrf()

        img_client.setex('random_%s' % mobile, 300, random_str)

        access_token = SecretOauth().dumps(random_str)

        # 3.返回响应
        return http.JsonResponse({'status': 5000, "mobile": mobile, "access_token": access_token})

# 发送短信
class FindPasswordSendSmsCodeView(View):
    def get(self, request, mobile):

        # 1.接收access_token 解密 校验是否准确
        access_token = request.GET.get('access_token')
        # 解密前端 传入的
        loads_acces_token = SecretOauth().loads(access_token)

        # 获取后台存储的
        redis_client = get_redis_connection('verify_image_code')
        redis_random_token = redis_client.get('random_%s' % mobile)
        if loads_acces_token != redis_random_token.decode():
            return http.JsonResponse({"status": 5001, 'message': "token错误!"})

        # * 3.生成随机 6位 短信验证码内容 random.randit()
        from random import randint
        sms_code = '%06d' % randint(0, 999999)
        # *   4.存储 随机6位 redis里面(3步 )
        sms_client = get_redis_connection('sms_code')

        # 1.获取 频繁发送短信的 标识
        send_flag = sms_client.get('send_flag_%s' % mobile)

        # 2.判断标识 是否存在
        if send_flag:
            return http.JsonResponse({'code': '4001', 'errmsg': '发送短信过于频繁66'})

        # 3.标识不存在 ,重新倒计时
        p1 = sms_client.pipeline()
        p1.setex('send_flag_%s' % mobile, 60, 1)
        p1.setex('sms_%s' % mobile, 300, sms_code)
        p1.execute()
        # *   5.发短信---第三方容联云--
        print("原始短信:", sms_code)
        # from celery_tasks.sms.tasks import ccp_send_sms_code
        # ccp_send_sms_code.delay(mobile, sms_code)
        #

        # *   6.返回响应对象
        return http.JsonResponse({"status": 200, 'message': "短信发送成功!"})

# 第二步提交
class SecondView(View):
    def get(self, request, mobile):
        sms_code = request.GET.get('sms_code')

        # 1.校验手机号
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            return http.JsonResponse({"status": 5004})

        # 2.校验验证码
        sms_client = get_redis_connection('sms_code')
        redis_sms_code = sms_client.get('sms_%s' % mobile)

        if sms_code != redis_sms_code.decode():
            return http.JsonResponse({"status": 5001})

        # 3.返回正确的响应
        redis_client = get_redis_connection('verify_image_code')
        redis_random_token = redis_client.get('random_%s' % mobile)
        access_token = SecretOauth().dumps(redis_random_token.decode())

        return http.JsonResponse({"status": 5000, "user_id": user.id, "access_token": access_token})

# 重置密码 + 第三步提交
class UserNewPasswordView(View):
    def post(self, request, user_id):

        json_dict = json.loads(request.body.decode())
        password = json_dict.get('password')
        password2 = json_dict.get('password2')
        access_token = json_dict.get('access_token')


        if not all([password,password2,access_token]):
            return http.HttpResponseForbidden('参数不能为空!')

        # 解密前端 传入的
        loads_acces_token = SecretOauth().loads(access_token)

        if not re.match('^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # *   3.确认密码: ---------判空,判断是否相等
        if password2 != password:
            return http.HttpResponseForbidden('两次密码输入不一致')


        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return http.JsonResponse({"status": 5002, 'message': "user_id有误!"})

        redis_client = get_redis_connection('verify_image_code')
        redis_random_token = redis_client.get('random_%s' % user.mobile)
        if loads_acces_token != redis_random_token.decode():
            return http.JsonResponse({"status": 5001, 'message': "token错误!"})

        # 更新密码
        user.set_password(password)
        user.save()

        return http.JsonResponse({"status": 5000, 'message': "密码设置成功!"})


