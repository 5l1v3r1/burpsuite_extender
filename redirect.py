#!/usr/bin/env python
#coding = utf-8
#2017.8.7  0.1  get all needed information from burpsuite
#2017.8.8 0.2   repeater the request by httplib
#2017.8.8 0.2.1 newest

#Burpsuite module
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IRequestInfo
from burp import IResponseInfo
from burp import IParameter
from burp import IScanIssue


#python module
from urllib import unquote,quote
import httplib
import urlparse

#Extender describre
print 'Check open redirect issue'

    
class BurpExtender(IBurpExtender,IHttpListener,IRequestInfo,IResponseInfo,IParameter,IHttpRequestResponse,IScanIssue):
    
    
    def registerExtenderCallbacks(self,callbacks):
        
        #keep a reference to our callbacks object
        self._callbacks = callbacks
        
        #helper methods
        self._helpers = callbacks.getHelpers()
        
        
        #define name
        self._callbacks.setExtensionName("RedirectIssue")
        
        #register a HttpListener to listen all http
        callbacks.registerHttpListener(self)
        
        
    def processHttpMessage(self,toolFlag,messageIsRequest,messageInfo):

        #only identify Proxy
        if toolFlag == 4 or toolFlag == 64:

            #identify Response
            if not messageIsRequest:

                #get Response
                response = messageInfo.getResponse()
                #get ReponseInfo
                analyzedResponse = self._helpers.analyzeResponse(response)
                
                #identify status
                StatusCode = analyzedResponse.getStatusCode()
                
                if StatusCode == 302 or StatusCode == 301:
                    
                    #Location details
                    Headers = analyzedResponse.getHeaders()
                    for header in Headers:
                        if header.startswith('Location:'):    
                            LocationDetail = header
                            break
                        else:
                            LocationDetail =''

                     
                    #redirect is exist   
                    
                    analyzeRequest = self._helpers.analyzeRequest(messageInfo.getHttpService(),messageInfo.getRequest())                      
        
                    for re_header in analyzeRequest.getHeaders():
                        if re_header.startswith('Cookie'):    
                            Cookie = re_header
                            break
                        else:
                            Cookie =''
                    
                    
                    #identify all parameters
                    _Parameters = analyzeRequest.getParameters()

                    #define a new parameters
                    newParameters = []
                    
                    #print _Parameters
                    for _Parameter in _Parameters:
                                #Issue:AttributeError: 'unicode' object has no attribute 'getType'
                                #the _ will make type be unicode!!!
        
                        if _Parameter.getType() == _Parameter.PARAM_URL:
                            parameter_key = _Parameter.getName()
                            parameter_value = _Parameter.getValue()    

                            #identify if value is in location
                            if unquote(LocationDetail).find(unquote(parameter_value)):
                                #identify if it is Oauth and the value of state is not encrypted
                                if parameter_key.find('state') != -1 and parameter_value.find('/') != -1 and parameter_value.find('g0da.org') == -1:
                                    new_parameter = '%2f%2fg0da.org%23' # need more payload
                                    _Parameter = self._helpers.buildParameter(parameter_key,new_parameter,_Parameter.getType())
                                #identify if the redirect is value's parameter
                                elif (parameter_key.find('uri') != -1 or parameter_key.find('url') != -1) and (parameter_value.find('http') != -1 or parameter_value.find('https') != -1) and (parameter_value.find('url=') != -1 or parameter_value.find('uri=') !=-1) and parameter_value.find('g0da.org') == -1:
                                    u = urlparse.urlparse(parameter_value)
                                    q = u.query
                                    p = q.split('=')[0]
                                    new_parameter = quote(u.scheme+"://"+u.netloc+u.path+"?"+p+"=//g0da.org").replace('%2F','/')
                                    _Parameter = self._helpers.buildParameter(parameter_key,new_parameter,_Parameter.getType())
                                #created in own
                                elif (parameter_key.find('url')!= -1 or parameter_key.find('uri') != -1 or parameter_key.find('next') != -1) and parameter_value.find('g0da.org') == -1:#maybe we have to find more
                                    new_parameter = '@g0da.org%23'+parameter_value # need more payload
                                    _Parameter = self._helpers.buildParameter(parameter_key,new_parameter,_Parameter.getType())
                                
                            newParameters.append(_Parameter)
                        
                    newUrl = str(analyzeRequest.getUrl()).split('?')[0]+"?"
                    #NewParameters is ok!!                    
                    for par in newParameters:
                        #print par.getName()+"=>"+par.getValue()
                        newUrl = newUrl+par.getName()+"="+par.getValue()+"&"
                    
                    #we have newUrl
                    newUrl = newUrl[:-1]
                    Cookie = str(Cookie)[7:]
                    
                    reUrl = urlparse.urlparse(newUrl)
                    if reUrl.scheme == 'http':
                        conn = httplib.HTTPConnection(reUrl.netloc)
                    elif reUrl.scheme == 'https':
                        conn = httplib.HTTPSConnection(reUrl.netloc)
                    
                    url = reUrl.path
                    if reUrl.query: url += '?' + reUrl.query
                    if reUrl.fragment: url += '#' + reUrl.fragment
                    if not url: url = '/'
                    conn.request(method='GET', url=url , headers={'Cookie': Cookie})
                    
                    identifyResponse = conn.getresponse()
                    
                    if identifyResponse.status == 302 or identifyResponse.status == 301:
                        location = identifyResponse.getheader('location')
                        if location.find('g0da.org') != -1 and location.find('error') == -1:
                            print "yes\n=>"+reUrl.scheme+"://"+reUrl.netloc+url+"\n=>"+location
                            def getIssueName():
                                return "Open Redirect"

                        else:
                            print "no\n=>"+reUrl.scheme+"://"+reUrl.netloc+url+"\n=>"+location
                    else:
                        print "no"
                    
                    

