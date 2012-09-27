#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import datetime
import markdown
import os
import re
from node_detect import *
from util import *
from flask import (
    Flask, render_template, request, url_for, flash, redirect,
    send_from_directory, Markup, abort
    )
from flask.ext.admin import Admin
from flaskext.cache import Cache
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.wtf import (
    validators, ValidationError, Form, TextField,
    PasswordField, TextAreaField,
    FileField, HiddenField, Required, EqualTo
    )
from flask.ext.admin.contrib.sqlamodel import ModelView
from flask.ext.login import (
    LoginManager, current_user, login_required, login_user, logout_user, 
    UserMixin, AnonymousUser, confirm_login, fresh_login_required
    )
from flask.ext.gravatar import Gravatar
from jinja2 import evalcontextfilter, Markup, escape

_paragraph_re = re.compile(r'(?:\r\n|\r|\n){2,}')

# Flask
app = Flask(__name__)
app.config.from_object('basement.config')
# Flask-cache
cache = Cache(app)
# Flask-login
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
@login_manager.user_loader
def load_user(id):
    return Users.query.filter_by(id=int(id)).first()
login_manager.setup_app(app)

# Flask-SQLAlchemy
db = SQLAlchemy(app)

# Flask-Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False)

# models
class Anonymous(AnonymousUser):
    name = u"Anonymous"

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode(45), unique=True)
    nickname = db.Column(db.Unicode(45))
    email = db.Column(db.Unicode(45))
    salt = db.Column(db.Unicode(8))
    password = db.Column(db.Unicode(100))
    ctime = db.Column(db.DateTime)
    active = db.Column(db.Integer, default=1)
    bio = db.Column(db.Unicode(45))
    photo = db.Column(db.Unicode(45), default=u"default_avatar.jpg")
    topics = db.relationship('Topics', cascade='all', backref='user', lazy='dynamic')
    comments = db.relationship('Comments', cascade='all', backref='user', lazy='dynamic')

    def is_active(self):
        return self.active > 0

    def __unicode__(self):
        return self.username

Topics_nodes = db.Table('topics_nodes',
    db.Column('topic_id', db.Integer, db.ForeignKey('topics.id')),
    db.Column('node_id', db.Integer, db.ForeignKey('nodes.id'))
    )

class Topics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Unicode(200))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    contents = db.Column(db.Text)
    ctime = db.Column(db.DateTime)
    rate = db.Column(db.Float)
    comments = db.relationship('Comments', cascade='all', backref='topic',
     lazy='dynamic')
    visits = db.Column(db.Integer, default=0)
    last_replied = db.Column(db.DateTime)
    # tags = db.relationship('Tags', cascade='all', backref='topic', lazy='dynamic')
    nodes = db.relationship('Nodes', secondary=Topics_nodes, 
        backref=db.backref('topic', lazy='dynamic'))

    def count_comments(self):
        return len(self.comments.all())

    def __unicode__(self):
        return self.title

class Nodes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Unicode(45))
    url = db.Column(db.Unicode(45))
    active = db.Column(db.Integer())
    ctime = db.Column(db.DateTime())
    topic_num = db.Column(db.Integer())
    # topics = db.relationship('Topics', secondary=Topics_nodes, 
    #     backref=db.backref('node', lazy='dynamic'))

    def __unicode__(self):
        return self.value

class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contents = db.Column(db.Text)
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    reply_to = db.Column(db.Integer, db.ForeignKey('comments.id'))
    # comments = db.relationship('Comments', backref='comment', lazy='dynamic')
    ctime = db.Column(db.DateTime)

    def __unicode__(self):
        return self.contents


class Tags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Unicode(45))
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'))

    def __init__(self, value, topic_id):
        self.value = value
        self.topic_id =topic_id

    def __unicode__(self):
        return '<Tag %s for %s>' % (self.value, self.topic_id)

# forms
class LoginForm(Form):
    username = TextField(u'User Name', validators=[Required()])
    password = PasswordField(u'Password', validators=[Required()])

class SignupForm(Form):
    username = TextField(u'Username', validators=[Required()])
    email = TextField(u'Email', validators=[validators.Email()])
    password = PasswordField(u'Password', validators=[Required()])

    def validate_username(form, field):
        if Users.query.filter_by(username=field.data).first():
            raise ValidationError('Username exsits.')

class TopicForm(Form):
    title = TextField(u'Title', validators=[Required()])
    contents = TextAreaField(u'Contents')

class CommentsForm(Form):
    contents = TextAreaField(u'Comments', validators=[Required()])

class SettingsForm(Form):
    # nickname = TextField(u'Name')
    email = TextField(u'Email', validators=[Required()])
    bio = TextAreaField(u'Bio')
    photo = FileField(u'Photo',
        validators = [validators.regexp(
            ur'^[^/\\]\.(jpg|jpeg|png|gif|JPG|JPEG|PNG|GIF)$'
            )])

class ChangePasswordForm(Form):
    old_password = PasswordField(u'Old Password', validators=[Required()])
    new_password = PasswordField(u'New Password', validators=[Required()])
    confirm = PasswordField(u'Repeat Password', validators=[
        Required(), EqualTo('new_password', message='Passwords must match')]
        )

# views
@app.route('/signup', methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated():
        flash('You are logged in', 'error')
        redirect('/')
    b = browser(request)
    form = SignupForm()
    if form.validate_on_submit():
        user = Users()
        user.username = request.form['username']
        user.nickname = request.form['username']
        user.email = request.form['email']
        user.salt = get_salt()
        user.password = encrypt_password(request.form['password'])
        user.ctime = datetime.now()
        db.session.add(user)
        db.session.commit()
    return render_template('signup.html', **locals())
    
@app.route("/login", methods=["GET", "POST"])
def login():
    b = browser(request)
    form = LoginForm()
    if form.validate_on_submit():
        username = request.form['username']
        user = Users.query.filter_by(username=username).first()
        if not user:
            flash('Please check your username or password', 'error')
            redirect('/login')
        password = encrypt_password(request.form['password'], user.salt)
        if not user or user.password == password:
            if login_user(user, remember=False):
                flash('Logged in', 'success')
                return redirect(request.args.get("next") or url_for('index'))
        else:
            flash('error when logging', 'error')
    return render_template('login.html', **locals())

@app.route('/logout', methods=['GET'])
def logout():
    b = browser(request)
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("index"))

@app.route('/', methods=['GET'])
def index():
    b = browser(request)
    topics = Topics.query.order_by("last_replied desc").limit(100).all()
    return render_template('index.html', **locals())

@app.route('/topic/<int:topic_id>/delete', methods=['POST'])
@login_required
def topic_delete(topic_id):
    b = browser(request)
    topic = Topics.query.filter_by(id=topic_id).first_or_404()
    if current_user.id != topic.user_id:
        return abort(404)
    db.session.delete(topic)
    db.session.commit()
    flash('Topic has been deleted!', 'success')
    return redirect('/')

@app.route('/topic/<int:topic_id>/edit', methods=['POST', 'GET'])
@login_required
def topic_edit(topic_id):
    b = browser(request)
    topic = Topics.query.filter_by(id=topic_id).first_or_404()
    if current_user.id != topic.user_id:
        return abort(404)
    form = TopicForm()
    if form.validate_on_submit():
        topic.title = request.form['title']
        topic.contents = request.form['contents']
        db.session.commit()
        flash('You have edited the topic', 'success')
        return redirect('/topic/' + str(topic_id))
    return render_template('topic_edit.html', **locals())

@app.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
def topic(topic_id):
    b = browser(request)
    form = CommentsForm()
    topic = Topics.query.filter_by(id=topic_id).first_or_404()
    topic.visits += 1
    db.session.add(topic)
    db.session.commit()
    comments = Comments.query.filter_by(topic_id=topic_id).all()
    replied_comments = dict()
    for item in comments:
        if item.reply_to != 0:
            replied_comments.setdefault(item.reply_to, list())
            replied_comments[item.reply_to].append(item)
    if form.validate_on_submit():
        topic.last_replied = datetime.now()
        comment = Comments()
        comment.topic_id = topic_id
        comment.user_id = request.form['user_id']
        comment.contents = request.form['contents']
        comment.ctime = datetime.now()
        comment.reply_to = request.form['reply_to']
        db.session.add(comment)
        db.session.commit()
        flash('Replied successful', 'success')
        return redirect('/topic/' + str(topic_id))
    return render_template('topic.html', **locals())

@app.route('/post', methods=['GET','POST'])
@login_required
def post():
    b = browser(request)
    form = TopicForm()
    if form.validate_on_submit():
        topic = Topics()
        topic.title = request.form['title']
        topic.user_id = request.form['user_id']
        topic.contents = request.form['contents']
        topic.ctime = datetime.now()
        topic.last_replied = topic.ctime
        db.session.add(topic)
        db.session.commit()
        nodes = overall_detect(topic.id, topic.title)
        return redirect('/topic/' + str(topic.id))
    return render_template('post.html', **locals())

@app.route('/settings', methods=['GET','POST'])
@login_required
def settings():
    b = browser(request)
    form = SettingsForm()
    user = Users.query.filter_by(id=current_user.id).first()
    # if form.validate_on_submit():
    if request.method == 'POST':
        # user.nickname = request.form['nickname']
        user.email = request.form['email']
        user.bio = request.form['bio']
        db.session.add(user)
        db.session.commit()
        flash('You\'v updated your settings', 'success')
        redirect('/settings')
    return render_template('settings.html', **locals())

@app.route('/settings/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    b = browser(request)
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if request.form['old_password'] != current_user.password:
            flash('Old password wrong!', 'error')
            redirect(url_for('change_password'))
        else:
            current_user.password = encrypt_password(
                request.form['new_password'], current_user.salt
                )
            db.session.add(current_user)
            db.session.commit()
            flash('Password changed', 'success')
            redirect(url_for('index'))
    return render_template('change_password.html', **locals())

@app.route('/u/<username>', methods=['GET'])
def u(username):
    b = browser(request)
    user = Users.query.filter_by(username=username).first_or_404()
    return render_template('u.html', **locals())

@app.route('/page/<page>', methods=['GET'])
def page(page):
    b = browser(request)
    return render_template('/page/%s.html' % page)

@app.route('/favicon.ico', methods=['GET'])
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'), 'favicon.ico'
        )

@app.errorhandler(404)
def page_not_found(error):
    b = browser(request)
    return render_template('404.html', **locals()), 404

@app.template_filter()
@evalcontextfilter
def nl2br(eval_ctx, value):
    result = u'\n\n'.join(u'<p>%s</p>' % p.replace('\n', '<br>\n') \
        for p in _paragraph_re.split(value))
    if eval_ctx.autoescape:
        result = Markup(result)
    return result

@app.template_filter()
def make_markdown(value):
    return Markup(markdown.markdown(value))

@app.template_filter()
def escape_script(value):
    value = value.replace('<script', '')
    # value = value.replace('</a', '')
    return value

@app.template_filter()
def mention(value):
    value = Markup(value).unescape()
    # pat = re.compile(ur'(@\w+)\b(?!.cn)\b(?!.com)\b(?!.org)\b(?!.net)')
    pat = re.compile(ur'(@\S+)')
    m = u'<a href="/u/%s">%s</a> '
    try:
        users = pat.findall(value)
        for i in users:
            if Users.query.filter_by(username=i[1:]).first():
                value = value.replace(i, m % (i[1:],i))
    except:
        pass

    res = markdown.markdown(value)
    return Markup(res)

@app.template_filter()
def timesince(dt, default="just now"):
    """
    Returns string representing "time since" e.g.
    3 days ago, 5 hours ago etc.
    """
    now = datetime.now()
    diff = now - dt
    # if diff > 1 day, return original time format
    if int(diff.total_seconds()) > 60 * 60 * 24:
        return dt
    periods = (
        (diff.days / 365, "year", "years"),
        (diff.days / 30, "month", "months"),
        (diff.days / 7, "week", "weeks"),
        (diff.days, "day", "days"),
        (diff.seconds / 3600, "hour", "hours"),
        (diff.seconds / 60, "minute", "minutes"),
        (diff.seconds, "second", "seconds"),
    )
    for period, singular, plural in periods:
        if period:
            return "%d %s ago" % (period, singular if period == 1 else plural)
    return default

# if __name__ == '__main__':
#     admin = Admin(app)
#     admin.add_view(ModelView(Users, db.session))
#     admin.add_view(ModelView(Topics, db.session))
#     admin.add_view(ModelView(Comments, db.session))
