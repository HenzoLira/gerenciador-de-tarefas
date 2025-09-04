from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
from functools import wraps

# --- Configuração Inicial ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'sua-chave-secreta-muito-segura'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Decorador de Admin ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- Models ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) 
    role = db.Column(db.String(20), nullable=False, default='user')
    tasks = db.relationship('Task', backref='owner', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='pendente')
    due_date = db.Column(db.Date, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Rotas da Aplicação ---
@app.route('/')
@login_required
def dashboard():
    user_tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.due_date).all()
    return render_template('dashboard.html', tasks=user_tasks)

@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task_to_edit = Task.query.get_or_404(task_id)
    if task_to_edit.owner != current_user:
        abort(403)
    if request.method == 'POST':
        task_to_edit.title = request.form.get('title')
        task_to_edit.description = request.form.get('description')
        due_date_str = request.form.get('due_date')
        task_to_edit.due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date() if due_date_str else None
        db.session.commit()
        flash('Tarefa atualizada com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_task.html', task=task_to_edit)

@app.route('/add_task', methods=['POST'])
@login_required
def add_task(
):
    title = request.form.get('title')
    description = request.form.get('description')
    due_date_str = request.form.get('due_date')
    due_date_obj = datetime.strptime(due_date_str, '%Y-%m-%d').date() if due_date_str else None
    if title:
        new_task = Task(title=title, description=description, due_date=due_date_obj, owner=current_user)
        db.session.add(new_task)
        db.session.commit()
        flash('Tarefa adicionada com sucesso!', 'success')
    else:
        flash('O título da tarefa é obrigatório.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/update_task/<int:task_id>')
@login_required
def update_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    task.status = 'concluída'
    db.session.commit()
    flash('Tarefa marcada como concluída!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    task_to_delete = Task.query.get_or_404(task_id)
    if task_to_delete.owner != current_user and current_user.role != 'admin':
        abort(403)
    db.session.delete(task_to_delete)
    db.session.commit()
    flash('Tarefa excluída com sucesso!', 'warning')
    if current_user.role == 'admin' and request.referrer and 'admin' in request.referrer:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('dashboard'))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    all_tasks = Task.query.order_by(Task.due_date).all()
    return render_template('admin.html', tasks=all_tasks)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Este email já está cadastrado. Tente fazer login.', 'warning')
            return redirect(url_for('login'))
        password_hash = generate_password_hash(password)
        new_user = User(username=username, email=email, password=password_hash)
        db.session.add(new_user)
        db.session.commit()
        flash('Cadastro realizado com sucesso! Faça o login para continuar.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Email ou senha inválidos. Tente novamente.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)