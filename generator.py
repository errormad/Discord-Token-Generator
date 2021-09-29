from requests.models import Response
from httpx import Client
from discord_build_info_py import *
from base64 import b64encode as b
from hcapbypass import bypass

import json
import urllib3
import random
import string
import time
import discum
import random

urllib3.disable_warnings()


usernames = []
for line3 in open('usernames.txt', encoding="utf-8"):
    usernames.append(line3.replace('\n', ''))

class TokenGenerator:
    def __init__(self, verbose, proxy):
        self.VerboseOutput = verbose
        self.UsedProxy = proxy
        self.session = Client(proxies={"https://": f"http://{self.UsedProxy}"})

        dcfduid, sdcfduid = self.GetDcfduid()
        self.dcfduid = dcfduid
        self.sdcfduid = sdcfduid
        self.session.cookies['__dcfduid'] = dcfduid
        self.session.cookies['__sdcfduid'] = sdcfduid
        self.session.cookies['locale'] = 'it'

        fingerprint = self.GetFingerprint()
        self.fingerprint = fingerprint

        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
        build_num, build_hash, build_id = getClientData('stable')

        self.super_properties = b(json.dumps({
            "os": "Windows",
            "browser": "Firefox",
            "device": "",
            "system_locale": "it-IT",
            "browser_user_agent": user_agent,
            "browser_version": "90.0",
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": int(build_num),
            "client_event_source": None
        }, separators=(',', ':')).encode()).decode()

    def GetDcfduid(self):
        resp = self.session.get(
            'https://discord.com/register')
        return resp.cookies['__dcfduid'], resp.cookies['__sdcfduid']

    def GetFingerprint(self):
        return self.session.get("https://discordapp.com/api/v9/experiments", timeout=10).json()['fingerprint']

    def CreateAccount(self, payload, captcha=None):
        if captcha:
            payload['captcha_key'] = captcha

        headers = {
            'Accept':               '*/*',
            'Accept-Encoding':      'gzip, deflate, br',
            'Accept-Language':      'it',
            'Authorization':        'undefined',
            'Cache-Control':        'no-cache',
            'Connection':           'keep-alive',
            #'Content-Length':       str(len(str(payload).replace(' ', '').replace('None', 'null')) + 2),
            'Content-Type':         'application/json',
            'Cookie':               '__dcfduid=' + self.dcfduid + '; __sdcfduid=' + self.sdcfduid,
            'Host':                 'discord.com',
            'Origin':               'https://discord.com',
            'Pragma':               'no-cache',
            'Referer':              'https://discord.com/register',
            'Sec-Fetch-Dest':       'empty',
            'Sec-Fetch-Mode':       'cors',
            'Sec-Fetch-Site':       'same-origin',
            'TE':                   'Trailers',
            'User-Agent':           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            'X-Fingerprint':        self.fingerprint,
            'X-Super-Properties':   self.super_properties
        }

        return self.session.post('https://discord.com/api/v9/auth/register', headers=headers, json=payload).json()

    def GenerateToken(self):
        payload = { 
            'fingerprint':      self.fingerprint,
            'email':            ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '@gmail.com',
            'username':         random.choice(usernames),
            'password':         ''.join(random.choice(string.ascii_lowercase) for _ in range(25)),
            'invite':           None,
            'consent':          True,
            'date_of_birth':    "1999-11-01",
            'gift_code_sku_id': None,
            'captcha_key':      None
        }

        response = self.CreateAccount(payload)

        if 'captcha_key' in response:
            while 1:
                times = 0
                captcha_solved = bypass("f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34", "discord.com", self.UsedProxy)
                if captcha_solved != False:
                    break
                times += 1
                if times >= 5: return '[!] Captcha Fail'
            response = self.CreateAccount(payload, captcha_solved)

        if 'retry_after' in response:
            print("[!] Rate limit! ({})".format(str(response['retry_after'])))
            return ""
            time.sleep((response['retry_after'] / 1000) + 5000)
            response = self.CreateAccount(payload, bypass(
                "f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34", "discord.com", self.UsedProxy))

        if 'token' not in response:
            return response

        token = response["token"]
        print(token)
        return response