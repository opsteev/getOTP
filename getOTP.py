#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import re
import getopt
import sys
import os
import json
import getpass
import logging

'''
Script workflow:

            -> send http get request to https://sso.arubanetworks.com/idp/startSSO.ping?PartnerSpId=PRD:AED:SP&TargetResource=https://ase.arubanetworks.com/accounts/login/?next=/decode_aos_key
            -> post username and password to this url
            -> get sig req from the response text and the auth host
            -> post the sig to auth host
            -> Redirect url after auth done
            -> get sig response in the response text and post it to MOA auth server
            -> get SAML information and post to auth server
            -> Post REF and targetsource to the auth server
            -> get sessionid and csrftoken from ase.arubanetworks.com
            -> post token with the above values in cookies to get the OTP password

'''

orginalAuthUrl = "https://sso.arubanetworks.com/idp/startSSO.ping?PartnerSpId=PRD:AED:SP&TargetResource=https://ase.arubanetworks.com/accounts/login/?next=/decode_aos_key"
decodeURL = "https://ase.arubanetworks.com/api/decode_aos_key/"
decodeURLReferer = "https://ase.arubanetworks.com/decode_aos_key"
cookies = {}
defaultCookieFile = "./OTPCookieFile"
otpData = {
    "reason": "linux_cmds",
    "key": None,
    "decode_type": "aos"
}

def usage():
    print "Usage: %s [OPTIONS]" % (os.path.basename(sys.argv[0]))
    print "OPTIONS:"
    print "     -h, --help: help"
    print "     -d, --debug: enable debugging"
    print "     -u, --username=: username (this is your domain name)"
    print "     -p, --password=: password (your domain password)"
    print "     -c, --cookies: the cookies file (which you kept before)"
    print "     -s, --savecookies: save the cookies (can be used next time without typing username and password again)"
    print "     -t, --token: the token you get from IAP shell"

def enableDebugging():
    # These two lines enable debugging at httplib level (requests->urllib3->http.client)
    # You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
    # The only thing missing will be the response.body which is not logged.
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client
    http_client.HTTPConnection.debuglevel = 1

    # You must initialize logging, otherwise you'll not see debug output.
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def readCookies(cookieFile):
    with open(cookieFile) as f:
        ctx = f.read()
    return json.loads(ctx)

def writeCookiesTofile(filename = None):
    if filename is None:
        filename = defaultCookieFile
    with open(filename, 'w') as f:
        ctx = f.write(json.dumps(cookies))

def authArubaSSO(username, password):
    # Use session module to keep cookies
    global cookies
    session = requests.session()

    # Phase 1:
    phase1Request = session.get(orginalAuthUrl)
    print "Phase 1 Done."
    phase1AuthData = {
        'pf.username': username,
        'pf.pass': password,
        'pf.ok': '',
        'pf.cancel': ''
    }
    if False:
        # It seems it does not need phase2 to phase5 ??!
        # Phase 2:
        phase2Request = session.post(phase1Request.url, data=phase1AuthData)
        # Get post data which will be triggered via js
        m = re.search('Duo.init\((.+)\)', phase2Request.text, re.S)
        if m:
            phase2AuthData = m.group(1).strip()
        else:
            logging.debug("Phase 2 text: %s"%phase2Request.text)
            raise Exception('Auth failed in phase 2')
        # Convert to Dict
        phase2AuthDataDict = eval(phase2AuthData)
        phase2AuthDataDuo = phase2AuthDataDict['sig_request'].split(':')
        phase2AuthDataDuoSig = phase2AuthDataDuo[0]
        phase2AuthDataAppSig = phase2AuthDataDuo[1]
        print "Phase 2 Done."

        # Phase 3:
        phase3AuthUrl = "https://" + phase2AuthDataDict['host'] + "/frame/web/v1/auth?tx=" + phase2AuthDataDuoSig + "&parent=" + phase2Request.url
        phase3Auth = session.get(phase3AuthUrl)
        print "Phase 3 Done."

        # Phase 4:
        phase4AuthUrl = phase3AuthUrl
        phase4AuthData = {
            'parent': phase2Request.url,
            'java_version': '',
            'flash_version': '21.0.0.20',
            'screen_resolution_width': '1920',
            'screen_resolution_height': '1080',
            'color_depth': '24'
        }
        phase4Auth = session.post(phase4AuthUrl, data=phase4AuthData)
        print "Phase 4 Done."

        # Phase 5:
        phase5AuthUrl = phase1Request.url
        m = re.search('name="js_cookie" value="([^\"]+)"', phase4Auth.text, re.S)
        if m:
            phase5AuthDataSig = m.group(1).strip()
        else:
            raise Exception('Auth failed in phase 5')
        phase5AuthData = {
            'sig_response': phase5AuthDataSig + ':' + phase2AuthDataAppSig
        }
        phase5Auth = session.post(phase5AuthUrl, phase5AuthData)
        print "Phase 5 Done."
    else:
        phase5Auth = session.post(phase1Request.url, data=phase1AuthData)
    # Phase 6:
    # SAML auth
    m = re.search('name="SAMLResponse" value="(.+)"', phase5Auth.text)
    samlResponse = m.group(1)
    m = re.search('name="RelayState" value="(.+)"', phase5Auth.text)
    relayState = m.group(1)
    m = re.search('form method="post" action="(.+)"', phase5Auth.text)
    samlDest = m.group(1)
    phase6Auth = session.post(samlDest, data={'SAMLResponse':samlResponse, 'RelayState':relayState})
    print "Phase 6 Done."

    # Phase 7:
    m = re.search('form method="post" action="(.+)"', phase6Auth.text)
    authPhase7Host = m.group(1)
    m = re.search('name="TargetResource" value="(.+)"', phase6Auth.text)
    authPhase7TargetSource = m.group(1)
    m = re.search('name="REF" value="(.+)"', phase6Auth.text)
    authPhase7REF = m.group(1)
    phase7Auth = session.post(authPhase7Host, data={'TargetResource': authPhase7TargetSource, 'REF': authPhase7REF}, verify=False)
    print "Auth Done."

    # Last Phase:
    logging.debug("Phase 7 text: %s"%phase7Auth.text)
    # okay...this page has been changed
    if False:
        m = re.search("name='csrfmiddlewaretoken' value='(.+)'", phase7Auth.text)
    else:
        m = re.search("csrfToken: '(.+)'", phase7Auth.text)
    csrfToken =  m.group(1).strip()
    logging.debug("csrfToken: %s"%csrfToken)
    print "Getting password for token %s:" % otpData['key']
    tokenPost = session.post(decodeURL, headers={'Referer': decodeURLReferer, 'X-CSRFToken': csrfToken}, verify=False, data=json.dumps(otpData))
    logging.debug("tokenPost text %s"%tokenPost.text)
    print session.cookies
    my_cookies = requests.utils.dict_from_cookiejar(session.cookies)

    cookies['sessionid'] = my_cookies['sessionid']
    cookies['csrftoken'] = my_cookies['csrftoken']
    cookies['username'] = username

    return json.loads(tokenPost.text).get('password').strip('\x00')


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hdu:p:cst:", ["help", "debug", "username=","password=","cookies","savecookies","token="])
    except getopt.GetoptError as err:
        #print str(err)
        usage()
        sys.exit(2)
    debug = False
    saveCookies = False
    hasCookies = False
    username = None
    password = None
    token = None
    for o, a in opts:
        if o == "-d":
            debug = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ('-c', "--cookies"):
            hasCookies = True
        elif o in ('-s', "--savecookies"):
            saveCookies = True
        elif o in ('-u', '--username'):
            username = a
        elif o in ('-p', '--password'):
            password = a
        elif o in ('-t', '--token'):
            token = a
        else:
            usage()
            assert False, "Unknown option"
    if hasCookies:
        cookies = readCookies(defaultCookieFile)
    else:
        if username is None:
            username = raw_input("Username: ")
        if password is None:
            password = getpass.getpass()
    if token is None:
        token = raw_input("Token: ")

    otpData['key'] = token.replace('-','')
    otp = None

    if debug:
        enableDebugging()

    if hasCookies:
        print "Getting password for token %s:" % otpData['key']
        tokenPost = requests.post(decodeURL, headers={'Referer': decodeURLReferer, 'X-CSRFToken': cookies['csrftoken']}, verify=False, cookies=cookies, data=json.dumps(otpData))
        otp = json.loads(tokenPost.text).get('password').strip('\x00')
    else:
        otp = authArubaSSO(username, password)
    print "Password: %s" % otp
    if saveCookies:
        writeCookiesTofile()

if __name__ == '__main__':
    main()
