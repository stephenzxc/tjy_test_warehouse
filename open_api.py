#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2022/12/7 14:42
# @Author  : jingyuan
# @File    : open_api.py
# @Software: PyCharm
#签名

import json
import requests
import hashlib
import hmac
import urlparse
from datetime import datetime
amzdate=datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
dateStamp=amzdate.split('T')[0]
serviceTail = "@9(K"
reqHeaderHost = "Host"
reqHeaderApcDate = "X-APC-Date"
reqHeaderApcAuth = "Authorization"
reqHeaderApcProject = "X-APC-Project"
reqHeaderApcUser = "X-APC-User"
ALGORITHM = 'HMAC-SHA256'
serviceName = 'APC_OPENAPI.REST_API'
canonicalQueryString=''
res_config={'url':'https://apc3-test-3.atg.netease.com/openapis/v1/common/members','data':{"produce_type":2,"business_category_id":71},'method':'POST','params':''}
environment={'access_key':'weihl_test_access_key','secret_key':'BgjXAsU64VQS8zdBMovHBQ==','project_id':'1180','user_email':'hourunzhe@corp.netease.com'}

def getProjectId():
    return environment['project_id']
def getSecretKey():
    return environment['secret_key']
def getAccessKey():
    return environment['access_key']
def getUserEmail():
    return environment['user_email']
def sign(key, message):
    return hmac.new(key,message, hashlib.sha256).digest()
def getSignatureKey(secretKey, dateStamp, serviceName):
    kDate=sign(('A#P@C&.V!'+secretKey),dateStamp)
    kService = sign(kDate, serviceName)
    kSigning = sign(kService, serviceTail)
    return kSigning
getSignatureKey(getSecretKey(),dateStamp,serviceName)
def getAuthHeader():
    canonicalUri = urlparse.urlparse(res_config['url']).path
    httpMethod=res_config['method']
    canonicalQueryString=res_config['params']
    requestBody = json.dumps(res_config['data'],separators=(',',':'))
    if res_config['method'] == 'GET' or not requestBody:
        requestBody = ''
    hashedPayload =  hashlib.md5(requestBody).hexdigest()
    canonicalHeaders ='\n'.join([
        "{}:{}".format(reqHeaderHost,urlparse.urlparse(res_config['url']).hostname),
        "{}:{}".format(reqHeaderApcDate,amzdate),
        "{}:{}".format(reqHeaderApcProject,getProjectId()),
        "{}:{}".format(reqHeaderApcUser,getUserEmail())
                                 ]) + '\n'

    signedHeaders = ';'.join([reqHeaderHost,reqHeaderApcDate,reqHeaderApcProject,reqHeaderApcUser])
    canonicalRequestData='\n'.join([httpMethod,canonicalUri,canonicalQueryString,canonicalHeaders,signedHeaders,hashedPayload])
    hashedRequestData=hashlib.md5(canonicalRequestData).hexdigest()
    credentialScope='/'.join([dateStamp,serviceName])
    stringToSign='\n'.join([ALGORITHM, amzdate, credentialScope, hashedRequestData])
    signingKey=getSignatureKey(getSecretKey(), dateStamp, serviceName)
    signature=hmac.new(signingKey, stringToSign, hashlib.sha256).hexdigest()
    authHeader=ALGORITHM + ' ' + 'Credential=' + getAccessKey() + '/' + credentialScope + ', ' + 'SignedHeaders=' + signedHeaders + ', ' + 'Signature=' + signature
    return authHeader
headers={}
headers.update({reqHeaderApcDate:amzdate})
headers.update({reqHeaderApcProject:getProjectId()})
headers.update({reqHeaderApcUser:getUserEmail()})
headers.update({reqHeaderApcAuth:getAuthHeader()})
# print headers
print requests.post(url=res_config['url'],headers=headers).text


#接口断言
# import pymysql
# mysql=pymysql.connect(host="acp-officedev-130360-m.of2.dumbo.nie.netease.com", user="root",password="z4IZuv3iR9epWuNT",database="apc3_inner",charset="utf8")
# cursor = mysql.cursor()
# sql="SELECT demand_issue_id FROM issues WHERE id='{}'".format(res_config['url'].split('/')[-1])
# print sql
# r=cursor.execute(sql)
# print cursor.fetchone()
# demand_issue_id2=cursor.fetchone()
# print demand_issue_id2  #(692677,)
# print type(demand_issue_id2)    #'tuple'
# demand_issue_id2=demand_issue_id2[0]
# print demand_issue_id2
# if demand_issue_id1==demand_issue_id2:
#     print "pass"
# else:
#     print "no pass"
