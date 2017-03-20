# $language = "python"
# $interface = "1.0"

# This automatically generated script may need to be
# edited in order to work correctly.
import os
import re

def Main():
	cookie_flag =  False
	crt.Screen.Synchronous = True
	crt.Screen.Send("su" + chr(13))
	crt.Screen.WaitForString("Username (Please enter with @domain.com, in lowercase): ")
	if not os.path.exists('./OTPCookieFile'):
		username = crt.Dialog.Prompt("Type you email", "Username", "", False)
		password = crt.Dialog.Prompt("Type you password", "Password", "", True)
	else:
		with open('./OTPCookieFile', 'r') as f:
			cookies = f.read()
		m = re.search('"username": "([a-zA-Z\@\.]+)"', cookies)
		if m:
			username = m.group(1).strip()
			cookie_flag = True
		else:
			username = crt.Dialog.Prompt("Type you email", "Username", "", False)
			password = crt.Dialog.Prompt("Type you password", "Password", "", True)
	crt.Screen.Send(username + chr(13))
	#crt.Screen.WaitForString("Support Password: ")
	szResult = crt.Screen.ReadString("Support Password: ")
	m = re.search("Token: ([\dA-Z\-]+)", szResult)
	if m:
		token = m.group(1).strip()
	else:
		crt.Dialog.MessageBox("Get token failed")
		return
	if cookie_flag:
		cmd = "python ./getOTP.py -c -t %s"%token
	else:
		cmd = "python ./getOTP.py -s -u %s -p %s -t %s"%(username, password, token)
	output = os.popen(cmd)
	cnt = output.read()
	m = re.search("Password: ([\da-zA-Z]+)", cnt)
	if m:
		otp = m.group(1).strip()
	else:
		if cookie_flag:
			os.remove('./OTPCookieFile')
		crt.Dialog.MessageBox("Get otp failed, please do it manually or retry...")
		return
	crt.Screen.Send(otp + chr(13))
	crt.Screen.Synchronous = False
Main()
