from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, LoginForm, RegisterForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


#configure login manager
login_manager = LoginManager()
login_manager.init_app(app=app)



##CONFIGURE TABLES

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)

    posts = relationship("BlogPost", back_populates="author")

    comments = relationship('Comment', back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key = True)
    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship('User', back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")






with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        user_id = current_user.id
    else:
        user_id = None

    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user_id=user_id)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit() and request.method == 'POST':
        name = form.name.data
        email = form.email.data

        if db.session.query(User).filter_by(email=email).first():
            flash("Email already exists, please log in")
            return redirect(url_for('login'))


        password = form.password.data
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)

        new_user = User(name=name, email=email, password=hashed_password)
        
        with app.app_context():
            db.session.add(new_user)
            db.session.commit()

        flash("Account Created!")
        return redirect(url_for('login'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit() and request.method == 'POST':
        email = form.email.data
        password = form.password.data
        user = db.session.query(User).filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
                
            else:
                flash("Password Incorrect")
        else:
            flash("Email not found")
        
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()

    if form.validate_on_submit() and request.method == 'POST':
        comment_body = form.body.data

        comment = Comment(
            text=comment_body,
            comment_author=current_user,
            parent_post = requested_post,
        )

        db.session.add(comment)
        db.session.commit()


    if current_user.is_authenticated:
        if requested_post.author.id == current_user.id:
            current_users_post = True
        else:
            current_users_post = False
    else:
        current_users_post = False
    

    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, current_users_post=current_users_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in = current_user.is_authenticated)


@app.route("/new-post", methods=['POST', 'GET'])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
            author_id = current_user.id,
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@login_required
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
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    comments_to_delete = post_to_delete.comments
    post_user_id = post_to_delete.author.id
    current_user_id = current_user.id

    if post_user_id == current_user_id:

        for comment in comments_to_delete:
            comment_to_delete = db.session.query(Comment).filter_by(id=comment.id).first()
            db.session.delete(comment_to_delete)
            db.session.commit()
        db.session.delete(post_to_delete)
        db.session.commit()
    
    else:
        flash("Only post author can delete post!")

    return redirect(url_for('get_all_posts'))

@login_manager.user_loader
def load_user(user_id):
    current_user = db.session.query(User).filter_by(id=user_id).first()
    return current_user



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
