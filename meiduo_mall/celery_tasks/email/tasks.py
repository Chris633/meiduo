from django.conf import settings

from celery_tasks.main import app
# bind：保证task对象会作为第一个参数自动传入
# name：异步任务别名
# retry_backoff：异常自动重试的时间间隔 第n次(retry_backoff×2^(n-1))s
# max_retries：异常自动重试次数的上限

@app.task(bind=True, name="send_email", retry_backoff=3)
def send_verify_email(self,to_email,verify_url):

    # 发邮件
    from django.core.mail import send_mail
    try:
        send_mail(
            subject='美多商城激活邮件',
            message='',
            from_email=settings.EMAIL_FROM,
            recipient_list=[to_email],
            html_message='<p>尊敬的用户您好！</p>' \
                         '<p>感谢您使用美多商城。</p>' \
                         '<p>您的邮箱为：%s 。请点击此链接激活您的邮箱：</p>' \
                         '<p><a href="%s">%s<a></p>' % (to_email, verify_url, verify_url)

        )
    except Exception as e:
        raise self.retry(exe=e, max_retries=3)


