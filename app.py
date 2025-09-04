import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date

# Configuração do App
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'sua-chave-secreta-padrao')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialização do SQLAlchemy e do Flask-Login
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models (Modelos do Banco de Dados)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user')
    tasks = db.relationship('Task', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='pendente')
    due_date = db.Column(db.Date)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Função para carregar o usuário no Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Rotas da Aplicação ---
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.due_date.desc()).all()
    return render_template('dashboard.html', tasks=tasks)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('dashboard'))
        flash('Email ou senha incorretos.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash('Este email já está cadastrado.', 'danger')
            return redirect(url_for('register'))
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Cadastro realizado com sucesso! Agora você pode fazer o login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('login'))

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    title = request.form.get('title')
    description = request.form.get('description')
    due_date_str = request.form.get('due_date')
    due_date = date.fromisoformat(due_date_str) if due_date_str else None
    new_task = Task(title=title, description=description, due_date=due_date, user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()
    flash('Tarefa adicionada!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/update_task/<int:task_id>')
@login_required
def update_task(task_id):
    task = db.session.get(Task, task_id)
    if task and task.user_id == current_user.id:
        task.status = 'concluída'
        db.session.commit()
        flash('Tarefa concluída!', 'success')
    else:
        flash('Tarefa não encontrada ou você não tem permissão para editá-la.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = db.session.get(Task, task_id)
    if not task or task.user_id != current_user.id:
        flash('Tarefa não encontrada ou você não tem permissão para editá-la.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        task.title = request.form.get('title')
        task.description = request.form.get('description')
        due_date_str = request.form.get('due_date')
        task.due_date = date.fromisoformat(due_date_str) if due_date_str else None
        db.session.commit()
        flash('Tarefa atualizada com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_task.html', task=task)

@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    task = db.session.get(Task, task_id)
    if task and (task.user_id == current_user.id or current_user.role == 'admin'):
        db.session.delete(task)
        db.session.commit()
        flash('Tarefa excluída!', 'success')
    else:
        flash('Tarefa não encontrada ou você não tem permissão para excluí-la.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('dashboard'))
    tasks = Task.query.all()
    return render_template('admin.html', tasks=tasks)

# --- Comandos CLI para o Render ---
@app.cli.command("create-admin")
def create_admin():
    """Cria um usuário administrador padrão."""
    with app.app_context():
        # Verifica se já existe um usuário com o email de admin
        existing_user = User.query.filter_by(email='admin@admin.com').first()
        if not existing_user:
            # Se não existir, cria o novo usuário com a role de admin
            admin_user = User(username='admin', email='admin@admin.com', role='admin')
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("Usuário administrador criado com sucesso!")
        else:
            print("Usuário administrador já existe.")

# --- Execução da Aplicação ---
if __name__ == '__main__':
    app.run(debug=True)