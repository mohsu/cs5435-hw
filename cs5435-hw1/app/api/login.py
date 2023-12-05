from bottle import (
    get,
    post,
    redirect,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import create_user, get_user
from app.models.session import (
    delete_session,
    create_session,
    get_session_by_username,
    logged_in,
)
from app.models.breaches import get_breaches
from app.util.hash import hash_sha256, hash_pbkdf2
from app.scripts.breaches import load_breaches


@get('/login')
def login():
    return template('login')


@post('/login')
def do_login(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    error = None
    user = get_user(db, username)
    print(user)
    if (request.forms.get("login")):
        if user is None:
            response.status = 401
            error = "{} is not registered.".format(username)
        else:
            salted_password = hash_pbkdf2(password, user.salt)
            if user.password != salted_password:
                response.status = 401
                error = "Wrong password for {}.".format(username)
            else:
                pass  # Successful login
    elif (request.forms.get("register")):
        if user is not None:
            response.status = 401
            error = "{} is already taken.".format(username)
        else:
            load_breaches(db)

            plaintext_breaches, hashed_breaches, salted_breaches = get_breaches(
                db, username)

            if plaintext_breaches:
                if password == plaintext_breaches[0].password:
                    error = "This password is breached (plain text), please use another one."

            elif hashed_breaches:
                hashed = hash_sha256(password)
                if hashed == hashed_breaches[0].hashed_password:
                    error = "This password is breached (hashed), please use another one."
            elif salted_breaches:
                salted = hash_pbkdf2(password, salted_breaches[0].salt)
                if salted == salted_breaches[0].salted_password:
                    error = "This password is breached (salted), please use another one."

            if not error:
                create_user(db, username, password)
    else:
        response.status = 400
        error = "Submission error."

    if error is None:  # Perform login
        existing_session = get_session_by_username(db, username)
        if existing_session is not None:
            delete_session(db, existing_session)
        session = create_session(db, username)
        response.set_cookie("session", str(session.get_id()))
        return redirect("/{}".format(username))
    return template("login", error=error)


@post('/logout')
@logged_in
def do_logout(db, session):
    delete_session(db, session)
    response.delete_cookie("session")
    return redirect("/login")
