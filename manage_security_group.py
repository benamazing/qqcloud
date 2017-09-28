#!/usr/bin/env python
# encoding=utf-8
#-*- coding: utf-8 -*-

'''
Dynamically update the security group, add host IP to the firewall for ssh to qq cloud VM
'''

import requests
import os
import json
import hashlib
import hmac
import base64
import time
import random



# security group domain name
sg_domain_name = 'dfw.api.qcloud.com'
sg_api_url = 'https://%s:/v2/index.php' % sg_domain_name

GET_METHOD = 'GET'
POST_METHOD = 'POST'


class SecurityGroupManager():
    def __init__(self, config_path=None):
        if config_path is None:
            config_path = os.path.dirname(__file__) + '/conf.json'
        self.config_path = config_path
        self.common_params = {}
        self.secret_key = ''
        with open(self.config_path) as f:
            conf_str = f.read()
            self.conf_json = json.loads(conf_str)
            self.common_params['Region'] = self.conf_json.get('Region', 'ap-shanghai')
            self.common_params['SecretId'] = self.conf_json.get('SecretId', '')
            self.common_params['SignatureMethod'] = self.conf_json.get('SignatureMethod', 'HmacSHA1')
            self.secret_key = self.conf_json.get('SecretKey')

    def get_rules_by_sgid(self, sgId):
        params = {}
        for k in self.common_params.keys():
            params[k] = self.common_params[k]
        params['Action'] = 'DescribeSecurityGroupPolicys'
        params['Timestamp'] = int(time.time())
        params['Nonce'] = random.randint(10000, 99999)
        params['sgId'] = sgId
        signature = generate_signature(params, sg_domain_name, self.secret_key)
        params['Signature'] = signature
        response = requests.get(sg_api_url, params=params)
        response.encoding = 'utf-8'
        return json.loads(response.content)

    def modify_rules_by_sgid(self, sgId):
        rules = self.get_rules_by_sgid(sgId)
        params = {}
        for k in self.common_params.keys():
            params[k] = self.common_params[k]
        params['Action'] = 'ModifySecurityGroupPolicys'
        params['Timestamp'] = int(time.time())
        params['Nonce'] = random.randint(10000, 99999)
        params['sgId'] = sgId
        for r in rules['data']['ingress']:
            if r['desc'] == 'temp':
                r['cidrIp'] = get_public_ip()
                break
        for i in range(len(rules['data']['ingress'])):
            for key in rules['data']['ingress'][i].keys():
                params['ingress.' + str(i) + '.' + key] = rules['data']['ingress'][i][key]
        #print(params)
        for i in range(len(rules['data']['egress'])):
            for key in rules['data']['egress'][i].keys():
                params['egress.' + str(i) + '.' + key] = rules['data']['egress'][i][key]
        signature = generate_signature(params, sg_domain_name, self.secret_key)
        params['Signature'] = signature
        response = requests.get(sg_api_url, params=params)
        response.encoding='utf-8'

        response_obj = json.loads(response.content)
        if response_obj['code'] == 0:
            print('Modify security group successfully!')
            return True
        else:
            print(response_obj['message'])
            return False

def generate_signature(params, domain_name, secret_key, request_method='GET', request_path='/v2/index.php'):
    if params is not None:
        sorted_keys = sorted(params.keys())
        sorted_items = []
        for k in sorted_keys:
            sorted_items.append('%s=%s' % (k.replace('_', '.'), params.get(k)))
        params_str = '&'.join(sorted_items)
        signature_origin_str = request_method + domain_name + request_path + '?' + params_str
        msg = bytes(signature_origin_str).encode('utf-8')
        secret = bytes(secret_key).encode('utf-8')
        if params.get('SignatureMethod', 'HmacSHA1') == 'HmacSHA256':
            signature = base64.b64encode(hmac.new(secret, msg, digestmod=hashlib.sha256).digest())
        else:
            signature = base64.b64encode(hmac.new(secret, msg, digestmod=hashlib.sha1).digest())
        return signature

def get_public_ip():
    try:
        response = requests.get('http://httpbin.org/ip')
        ip_json = json.loads(response.content)
        return(ip_json['origin'])
    except Exception as e:
        print(e)



if __name__ == '__main__':
    sg_manager = SecurityGroupManager()
    sgId = sg_manager.conf_json.get('sgId', '')
    old_rules = sg_manager.get_rules_by_sgid(sgId)
    print('Before update, the old rules for security groupd id {%s} are as follows: ' % sgId)
    print(json.dumps(old_rules, indent=True, sort_keys=True))
    sg_manager.modify_rules_by_sgid(sgId)

