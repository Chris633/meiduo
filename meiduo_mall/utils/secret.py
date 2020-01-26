from django.conf import settings
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

class SecretOauth(object):
    def __init__(self):
        self.serializer = Serializer(secret_key=settings.SECRET_KEY)

    # 加密
    def dumps(self, data):
        result = self.serializer.dumps(data)
        return result.decode()
    # 解密
    def loads(self, data):
        return self.serializer.loads(data)







# from itsdangerous import TimedJSONWebSignatureSerializer
#
# s = TimedJSONWebSignatureSerializer(secret_key='abc', expires_in=30)
# data_dict = {'openid': 'F1084s'}
#
# result = s.dumps(data_dict)
#
# print(s.loads(result))

