from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentsForm
from flask_wtf.csrf import CSRFProtect
from flask_gravatar import Gravatar
from functools import wraps
import os
from flask import session, app

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
# csrf token
csrf = CSRFProtect(app)
csrf.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


# user to gert the id of the currently logged in user
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


# log user out after 10 minutes
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=10)


# gravater initialization for comment images
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("Users", back_populates="posts")
    title = db.Column(db.String(150), unique=True, nullable=False)
    subtitle = db.Column(db.String(150), nullable=False)
    date = db.Column(db.String(150), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(150), nullable=False)
    # ***************Parent Relationship*************#
    comments = relationship("Comments", back_populates="parent_post")


class Comments(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship("Users", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

    # ***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    password = db.Column(db.Integer, unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    # *************** Parent Relationship *************#
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="comment_author")


# db.drop_all()
# db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If user current user isn't authenticated or id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        new_user = Users(
            email=register_form.email.data,
            password=generate_password_hash(method='pbkdf2:sha256',
                                            salt_length=16,
                                            password=register_form.password.data),
            name=register_form.name.data
        )
        user = Users.query.filter_by(email=register_form.email.data).first()
        if user:
            flash('User email already exist. Login instead!')
            return redirect(url_for("login"))
        login_user(new_user)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if request.method == 'POST':
        if login_form.validate_on_submit():
            # login code goes here
            email = login_form.email.data
            password = login_form.password.data
            user = Users.query.filter_by(email=email).first()
            # check if the user actually exists
            # take the user-supplied password, hash it, and compare it to the hashed password in the database
            if not user:
                flash('Email does not exist!', 'error')
                return redirect(url_for('login'))  # if the user doesn't exist or password is wrong, reload the page
            elif not check_password_hash(user.password, password):
                flash('Password is incorrect. Try again!', 'error')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = CommentsForm()
    if comments.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to login/register to comment!')
            return redirect(url_for('login'))

        new_comment = Comments(
            text=comments.body.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        comments.body.data = ""
        # return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        flash('Post successfully added!')
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        flash('Post successfully edited!')
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    flash('Post successfully deleted!')
    return redirect(url_for('get_all_posts'))


@app.route('/delete_comment/<int:post_id>/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def delete_comment(post_id, comment_id):
    specified_comment = Comments.query.get(comment_id)
    db.session.delete(specified_comment)
    db.session.commit()
    flash('Comment successfully deleted!')
    return redirect(url_for("show_post", post_id=post_id))


if __name__ == "__main__":
    app.run(debug=True)
