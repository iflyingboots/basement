#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import datetime
import markdown
import os
import re
import sys
from PIL import Image
from node_detect import *
from util import *
from flask import (
    Flask, render_template, request, url_for, flash, redirect,
    send_from_directory, Markup, abort
    )
# from flask.ext.admin import Admin
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
from flask.ext.uploads import *
from jinja2 import evalcontextfilter, Markup, escape

# import mdx_urlize module
sys.path.append(os.getcwd() + '/basement')

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
# Flask-Uploads
avatars = UploadSet('avatars', IMAGES)
photos = UploadSet('photos', IMAGES)
configure_uploads(app, (avatars,))

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
    notifications = db.relationship('Notifications', cascade='all', backref='user', lazy='dynamic')

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
    source = db.Column(db.Unicode(45))
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
    topics = db.relationship('Topics', secondary=Topics_nodes, 
        backref=db.backref('node', lazy='dynamic'))

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

class Notifications(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    type = db.Column(db.Integer)
    read = db.Column(db.Integer)
    ctime = db.Column(db.DateTime)
    param1 = db.Column(db.Integer)
    param2 = db.Column(db.Integer)
    param3 = db.Column(db.Integer)

    def __unicode__(self):
        return self.trans()

    def trans(self):
    # 1: user:param1 replied to topic:param2
        if self.type == 1:
            user = Users.query.filter_by(id=self.param1).first()
            topic = Topics.query.filter_by(id=self.param2).first()
            return '<a href="/u/%s">%s</a> replied to <a href="/topic/%d?nid=%d">%s</a>' % (
                user.username, user.username, topic.id, self.id, topic.title
                )
        # 2: user:param1 replied to your comment comment:param2
        elif self.type == 2:
            user = Users.query.filter_by(id=self.param1).first()
            comment = Comments.query.filter_by(id=self.param2).first()
            return '<a href="/u/%s">%s</a> replied to your comment: <a href="/topic/%d?nid=%d">%s</a>' % (
                user.username, user.username, comment.topic.id, self.id, comment.contents
                )
        # 3: user:param1 mentioned you on topic topic:param2
        elif self.type == 3:
            user = Users.query.filter_by(id=self.param1).first()
            topic = Topics.query.filter_by(id=self.param2).first()
            return '<a href="/u/%s">%s</a> mentioned you on <a href="/topic/%d?nid=%d">%s</a>' % (
                user.username, user.username, topic.id, self.id, topic.title
                )

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

    def validate_email(form, field):
        if Users.query.filter_by(email=field.data).first():
            raise ValidationError('Email exsits.')        

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

class MarkNotisForm(Form):
    user_id = TextField(u'', validators=[Required()])

# views
@app.route('/signup', methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated():
        flash('You are logged in', 'error')
        return redirect('/')
    b = browser(request)
    form = SignupForm()
    if form.validate_on_submit():
        user = Users()
        user.username = request.form['username']
        user.nickname = request.form['username']
        user.email = request.form['email']
        user.salt = get_salt()
        user.password = encrypt_password(request.form['password'], user.salt)
        user.ctime = datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('Signed up successful!', 'success')
        return redirect('/login')
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
@cache.cached(timeout=5)
def index():
    if current_user.is_authenticated():
        notis = get_unread(current_user.id)
    b = browser(request)
    notisForm = MarkNotisForm()
    topics = Topics.query.order_by("last_replied desc").limit(100).all()
    return render_template('index.html', **locals())

@app.route('/topic/<int:topic_id>/delete', methods=['POST'])
@login_required
def topic_delete(topic_id):
    b = browser(request)
    topic = Topics.query.filter_by(id=topic_id).first_or_404()
    if current_user.id != topic.user_id:
        return abort(404)
    delete_nodes(topic_id)
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
        delete_nodes(topic.id)
        overall_detect(topic.id, topic.title)
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
    # mark unread notification as read
    if request.args.get('nid'):
        mark_one(request.args.get('nid'))
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
        re_to = request.form['reply_to']
        # send notifications
        if re_to:
            comment.reply_to = re_to
            reply_to_user = Comments.query.get(re_to).user_id
            if reply_to_user != topic.user_id:
                send_notification(
                    reply_to_user,
                    2,
                    param1=current_user.id,
                    param2=re_to
                )
        if current_user.id != topic.user_id:
            send_notification(
                topic.user_id,
                1,
                param1=current_user.id,
                param2=topic_id
            )
        send_mention(request.form['contents'], current_user.id, topic.id)
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
        # send mention notifications
        send_mention(topic.contents, current_user.id, topic.id)
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
        if encrypt_password(request.form['old_password'], current_user.salt) != current_user.password:
            # flash('Old password wrong!', 'error')
            flash(request.form['old_password'])
            return redirect(url_for('change_password'))
        else:
            current_user.password = encrypt_password(
                request.form['new_password'], current_user.salt
                )
            db.session.add(current_user)
            db.session.commit()
            flash('Password changed', 'success')
            redirect(url_for('index'))
    return render_template('change_password.html', **locals())

@app.route('/settings/change_avatar', methods=['GET', 'POST'])
@login_required
def change_avatar():
    b = browser(request)    
    if request.method == 'POST' and 'avatar' in request.files:
        try:
            filename = avatars.save(
                request.files['avatar'], name='%s.' % (current_user.id,)
            )
            resize_avatar(filename, 'avatars')
            current_user.photo = filename
            db.session.commit()
            flash('Changed avatar', 'success')
            return redirect('/u/%s' % (current_user.username))
        except UploadNotAllowed:
            flash('Upload file not allowed', 'error')
            return redirect('/settings/change_avatar')
    return render_template('change_avatar.html', **locals())

@app.route('/u/<username>', methods=['GET'])
@cache.cached(timeout=60)
def u(username):
    b = browser(request)
    user = Users.query.filter_by(username=username).first_or_404()
    return render_template('u.html', **locals())

@app.route('/node/<value>', methods=['GET'])
def node(value):
    b = browser(request)
    node = Nodes.query.filter_by(url=value).first_or_404()
    return render_template('node.html', **locals())


@app.route('/notifications', methods=['GET'])
@login_required
@cache.cached(timeout=60)
def notifications():
    b = browser(request)
    notis = Notifications.query.filter_by(user_id=current_user.id).order_by('ctime desc').all()
    return render_template('notifications.html', **locals())

@app.route('/mark_notifications', methods=['POST'])
def mark_notifications():
    notis = Notifications.query.filter_by(read=0).all()
    for n in notis:
        n.read = 1
    db.session.commit()
    return 'Marked all notifications as read!'

@app.route('/page/<page>', methods=['GET'])
@cache.cached(timeout=6000)
def page(page):
    b = browser(request)
    return render_template('/page/%s.html' % page, **locals())

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

def send_mention(html, sender_id, topic_id):
    pat = re.compile(ur'(@\S+?)[\<\s+]')
    try:
        users = pat.findall(html)
        for i in users:
            u = Users.query.filter_by(username=i[1:]).first()
            if u:
                send_notification(
                    u.id,
                    3,
                    param1=sender_id,
                    param2=topic_id
                )
    except:
        pass

def mark_one(nid):
    notis = Notifications.query.filter_by(id=nid, read=0).first()
    if notis:
        notis.read = 1
        db.session.commit()

@app.template_filter()
def mention(value):
    res = markdown.Markdown(safe_mode=False, extensions=['urlize', 'nl2br'])
    res = res.convert(value)
    pat = re.compile(ur'(@\S+?)[\<\s+]')
    m = u'<a href="/u/%s">%s</a> '
    try:
        users = pat.findall(res)
        for i in users:
            if Users.query.filter_by(username=i[1:]).first():
                res = res.replace(i, m % (i[1:],i))
    except:
        pass
    return Markup(res)

@app.template_filter()
def avatar(u, size=50):
    if u.photo and u.photo != 'default_avatar.jpg':
        photo = '/static/uploads/avatars/'
        photo += '%s_%d.%s' % (
            u.photo.split('.')[0], size, u.photo.split('.')[1]
        )
        return photo
    return gravatar(u.email, size=size)

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

def resize_avatar(image, upload_type):
    path = os.path.join(UPLOADS_DEFAULT_DEST, upload_type, image)
    print path
    im = Image.open(path)
    ratio = float(im.size[0]) / float(im.size[1])
    name, ext = image.split('.')
    for i in (25, 50, 100):
        filename = os.path.join(UPLOADS_DEFAULT_DEST, upload_type, '%s_%d.%s' % (name, i, ext))
        im.resize((int(i), int(i/ratio)), Image.ANTIALIAS).save(filename)

def get_unread(user_id):
    return Notifications.query.filter_by(user_id=user_id, read=0).all()

def send_notification(user_id, type, **params):
    n = Notifications()
    n.user_id = user_id
    n.type = type
    n.read = 0
    n.ctime = datetime.now()
    #@TODO: not robust :(
    for k,v in params.items():
        setattr(n, k, v)
    db.session.add(n)
    db.session.commit()

# if __name__ == '__main__':
#     admin = Admin(app)
#     admin.add_view(ModelView(Users, db.session))
#     admin.add_view(ModelView(Topics, db.session))
#     admin.add_view(ModelView(Comments, db.session))
