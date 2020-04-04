#coding=utf8

from burp import IBurpExtender
from burp import IHttpListener
from burp import IContextMenuFactory
from javax.swing import JMenuItem

from base64 import b64decode, b64encode
from urllib import quote, unquote
import pyaes


class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):

        # your extension code here
        self._callbacks = callbacks

        # 用于获取IExtensionHelpers对象，扩展可以使用该对象执行许多有用的任务。返回：包含许多帮助器方法的对象，用于构建和分析HTTP请求等任务。
        self._helpers = callbacks.getHelpers()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。。
        self._callbacks.setExtensionName("Burp Crypto")
        # 注册一个 HTTP 监听器，那么当我们开启Burp监听的 HTTP 请求或收到的 HTTP 响应都会通知此监听器
        callbacks.registerHttpListener(self)

        # 注册菜单上下文
        # register message editor tab factory
        # callbacks.registerMessageEditorTabFactory(self)
        # register menu item factory
        callbacks.registerContextMenuFactory(self)
        return

    # 创建菜单右键
    def createMenuItems(self, invocation):
        self.invocation = invocation
        menu_list = []
        # flag参数控制加解密
        menu_list.append(JMenuItem("Use BurpCrypto to encrypt", None, actionPerformed=lambda x, flag=True: self.process(flag)))
        menu_list.append(JMenuItem("Use BurpCrypto to decrypt", None, actionPerformed=lambda x, flag=False: self.process(flag)))
        return menu_list

    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
    def get_request_info(self, request):
        # analyzeRequest用于分析HTTP请求，并获取有关它的各种关键详细信息。生成的IRequestInfo对象
        analyzedRequest = self._helpers.analyzeRequest(request)
        # 用于获取请求中包含的HTTP头。返回：请求中包含的HTTP标头。
        reqHeaders = analyzedRequest.getHeaders()
        # 获取消息正文开始的请求中的偏移量并从整个请求包中提取出请求Body
        reqBodys = request.getRequest()[analyzedRequest.getBodyOffset():]
        # 获取请求方法
        reqMethod = analyzedRequest.getMethod()
        # 获取请求中包含的参数
        reqParameters = analyzedRequest.getParameters()
        return analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters

    # 获取请求的参数名、参数值、参数类型（get、post、cookie->用来构造参数时使用）
    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType

    # Body处理
    def process(self, flag):
        # 获取当前请求
        currentRequest = self.invocation.getSelectedMessages()[0]
        # 提取请求各部分信息
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters = self.get_request_info(currentRequest)
        # 转换类型为字符串，方便进行字符串处理
        reqBodys = self._helpers.bytesToString(reqBodys)

        # 根据加密或解密的flag进行对应处理，框起部分自行根据实际情况变化
        # ================================
        if flag:
            # 加密操作
            _newBody = self.encrypt(reqBodys)
        elif not flag:
            # 解密操作
            _newBody = self.decrypt(unquote(reqBodys))
        # ================================

        # 转换类型
        newBody = self._helpers.stringToBytes(_newBody)
        # 刷新burp界面中的请求包
        newRequest = self._helpers.buildHttpMessage(reqHeaders, newBody)
        currentRequest.setRequest(newRequest)

    # 加密函数，自行根据实际情况变化
    def encrypt(self, text):
        crypto = AESCrypto()
        return crypto.encrypt(text)

    # 解密函数，自行根据实际情况变化
    def decrypt(self, text):
        crypto = AESCrypto()
        return crypto.decrypt(text)


class AESCrypto():
    def __init__(self):
        self.key = 'AAAAAAAAAAAAAAAA'
        self.iv = b'0000000000000000'
        self.aes = pyaes.AESModeOfOperationCBC(self.key, self.iv)
        # Block Size
        self.BS = 16
        # 字符填充函数：PKCS7Padding模式
        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        self.unpad = lambda s: s[0:-ord(s[-1])]

    def encrypt(self, text):
        encrypter = pyaes.Encrypter(self.aes)
        ciphertext = encrypter.feed(text)
        ciphertext += encrypter.feed()
        ciphertext = b64encode(ciphertext)
        return ciphertext

    def decrypt(self, text):
        decrypter = pyaes.Decrypter(self.aes)
        text = b64decode(text)
        decrypted = decrypter.feed(text)
        decrypted += decrypter.feed()
        return decrypted
