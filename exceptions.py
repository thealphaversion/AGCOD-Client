class BaseApiException(Exception):
    def __init__(self, message, *args, code=None, **kwargs):
        self.message = message
        self.args = args
        self.code = code
        self.kwargs = kwargs
        Exception.__init__(self, message)

    def __str__(self):
        return self.message


class ClientError(BaseApiException):
    pass