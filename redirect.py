#!/usr/bin/env python
#coding = utf-8
#2017.8.7  0.1


#Burpsuite module
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IRequestInfo
from burp import IResponseInfo
from burp import IParameter


#python module
from urllib import unquote
import urllib2

#Extender describre
print 'Check open redirect issue'





class BurpExtender(IBurpExtender,IHttpListener,IRequestInfo,IResponseInfo,IParameter,IHttpRequestResponse):
    
    
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
                        else:
                            LocationDetail =''
                    #redirect is exist   

                    analyzeRequest = self._helpers.analyzeRequest(messageInfo.getHttpService(),messageInfo.getRequest())                      
        
                            
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
                                if parameter_key.find('url')!= -1 or parameter_key.find('uri') != -1 or parameter_key.find('next') != -1 and not parameter_value.find('g0da.org'):#maybe we have to find more
                                    new_parameter = '%2f%2f@g0da.org' # need more payload
                                    _Parameter = self._helpers.buildParameter(parameter_key,new_parameter,_Parameter.getType())
                                
                            newParameters.append(_Parameter)
                        
                    newUrl = str(analyzeRequest.getUrl()).split('?')[0]+"?"
                    #NewParameters is ok!!                    
                    for par in newParameters:
                        #print par.getName()+"=>"+par.getValue()
                        newUrl = newUrl+par.getName()+"="+par.getValue()+"&"
                    
                    #we have newUrl
                    newUrl = newUrl[:-1]
                    
                    try:
                        identifyResponse = urllib2.urlopen(newUrl)
                    except urllib2.URLError as e:
                        if hasattr(e, 'reason'):
                            1
                        elif hasattr(e, 'code'):
                            1                      
                    #if it is new header
                    else:
                        if identifyResponse.geturl().find('g0da.org') and not identifyResponse.geturl().find('error'):
                            print "yes"
                        else:
                            print "no"


