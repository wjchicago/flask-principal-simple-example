from flask import Flask, current_app, request, session, render_template, redirect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_principal import Principal, Permission, RoleNeed, UserNeed, Identity, AnonymousIdentity, identity_changed, \
    identity_loaded, Denial
from flask_wtf import Form
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired


class Role:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name


class User(UserMixin):
    def __init__(self, uid, username, roles, password='password', active=True):
        self.id = uid
        self.username = username
        self.roles = roles
        self.password = password
        self.active = active

    @property
    def is_active(self):
        return self.active


# https://stackoverflow.com/questions/29500333/combining-roleneeds-with-flask-principal
class PermissionAnd(Permission):
    def allows(self, identity):
        if not PermissionAnd.has_all(self.needs, identity.provides):
            return False

        if self.excludes and self.excludes.intersection(identity.provides):
            return False

        return True

    @staticmethod
    def has_all(needed=None, provided=None):
        if needed is None:
            return True

        if provided is None:
            provided = set()

        shared = needed.intersection(provided)
        return shared == needed


user_list = [
    User(1, 'user1', [Role('A')]),
    User(2, 'user2', [Role('B')]),
    User(3, 'user3', [Role('C')]),
    User(4, 'user4', [Role('A'), Role('B')]),
    User(5, 'user5', [Role('A'), Role('C')]),
    User(6, 'user6', [Role('A'), Role('B')], False)
]

# define permissions
need_A = Permission(RoleNeed('A'))
need_B = Permission(RoleNeed('B'))
need_C = Permission(RoleNeed('C'))

# AND
need_A_and_B = PermissionAnd(RoleNeed('A'), RoleNeed('B'))

# OR - same as Permission(RoleNeed('A'), RoleNeed('B'))
need_A_or_B = Permission(RoleNeed('A')).union(Permission(RoleNeed('B')))

# NOT
need_not_A = Denial(RoleNeed('A'))


class LoginForm(Form):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


app = Flask(__name__)

app.config.update(
    DEBUG=True,
    SECRET_KEY='secret_key'
)

# init
principals = Principal(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(uid):
    return next(u for u in user_list if u.id == int(uid))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    # Validate form input
    if form.validate_on_submit():
        user = next(u for u in user_list if u.username == form.username.data)

        if user and form.password.data == user.password:
            # Keep the user info in the session using Flask-Login
            login_user(user, remember=True)

            # Tell Flask-Principal the identity changed
            identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))

            return redirect(request.args.get('next') or '/')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()

    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)

    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())

    return redirect(request.args.get('next') or '/')


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user

    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))

    if hasattr(current_user, 'roles'):
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role.name))


@app.route('/')
def index():
    return render_template('index.html', users=user_list)


@app.route('/need_A')
@need_A.require(http_exception=403)
def need_A():
    return "Role A is required. \n current_user name={}, roles={}".format(current_user.username, current_user.roles)


@app.route('/need_B')
@need_B.require(http_exception=403)
def need_B():
    return "Role B is required. \n current_user name={}, roles={}".format(current_user.username, current_user.roles)


@app.route('/need_C')
@need_C.require(http_exception=403)
def need_C():
    return "Role C is required. \n current_user name={}, roles={}".format(current_user.username, current_user.roles)


@app.route('/need_A_and_B')
@need_A_and_B.require(http_exception=403)
def need_A_and_B():
    return "Role A and Role B are both required. \n current_user name={}, roles={}".format(current_user.username, current_user.roles)


@app.route('/need_A_or_B')
@need_A_or_B.require(http_exception=403)
def need_A_or_B():
    return "Either Role A or Role B is required. \n current_user name={}, roles={}".format(current_user.username, current_user.roles)

@app.route('/need_not_A')
@need_not_A.require(http_exception=403)
def need_not_A():
    return "User with Role A cannot access here. \n current_user name={}, roles={}".format(current_user.username, current_user.roles)


if __name__ == '__main__':
    app.run()
