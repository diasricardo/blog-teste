from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Modelo de Postagem
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', back_populates='posts')
    
User.posts = db.relationship('Post', back_populates='author')

# Inicializa o banco de dados
with app.app_context():
    db.create_all()

# Página inicial (lista de postagens)
@app.route('/')
def home():
    posts = Post.query.all()
    return render_template('home.html', posts=posts)

# Página de registro de usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Cadastro realizado com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Email ou senha incorretos!', 'danger')
    return render_template('login.html')

# Página de logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('home'))

# Página de criação de postagem
@app.route('/create', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        flash('Você precisa estar logado para criar uma postagem!', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        new_post = Post(title=title, content=content, author_id=session['user_id'])
        db.session.add(new_post)
        db.session.commit()
        flash('Postagem criada com sucesso!', 'success')
        return redirect(url_for('home'))
    
    return render_template('create_post.html')

# Página de visualização de postagem
@app.route('/post/<int:id>')
def post(id):
    post = Post.query.get(id)
    return render_template('post.html', post=post)

# Página de edição de postagem
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_post(id):
    post = Post.query.get(id)
    if post.author_id != session.get('user_id'):
        flash('Você não tem permissão para editar essa postagem!', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        db.session.commit()
        flash('Postagem atualizada com sucesso!', 'success')
        return redirect(url_for('home'))

    return render_template('edit_post.html', post=post)

# Página de exclusão de postagem
@app.route('/delete/<int:id>')
def delete_post(id):
    post = Post.query.get(id)
    if post.author_id != session.get('user_id'):
        flash('Você não tem permissão para excluir essa postagem!', 'danger')
        return redirect(url_for('home'))

    db.session.delete(post)
    db.session.commit()
    flash('Postagem excluída com sucesso!', 'success')
    return redirect(url_for('home'))

@app.route('/post/<int:post_id>', methods=['GET'])
def post_details(post_id):
    # lógica para exibir o post com o id específico
    post = Post.query.get_or_404(post_id)
    return render_template('post_details.html', post=post)





if __name__ == '__main__':
    app.run(debug=True)
