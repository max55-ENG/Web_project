from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'secret-key-123'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# Модель поездки
class Ride(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    departure = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    seats = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    rides = Ride.query.all()
    return render_template('index.html', rides=rides)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Неверный email или пароль!', 'danger')
    return render_template('auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([username, email, password]):
            flash('Все поля обязательны!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email уже занят', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Имя пользователя занято', 'danger')
            return redirect(url_for('register'))

        try:
            new_user = User(
                username=username,
                email=email,
                password=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация успешна! Войдите в аккаунт', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('auth/register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/rides/create', methods=['GET', 'POST'])
@login_required
def create_ride():
    if request.method == 'POST':
        departure = request.form['departure']
        destination = request.form['destination']
        date_str = request.form['date']
        time_str = request.form['time']
        seats = int(request.form['seats'])
        price = int(request.form['price'])

        # Валидация
        try:
            ride_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if ride_date < datetime.now().date():
                flash('Дата должна быть в будущем!', 'danger')
                return redirect(url_for('create_ride'))
        except ValueError:
            flash('Некорректная дата!', 'danger')
            return redirect(url_for('create_ride'))

        if seats <= 0 or price <= 0:
            flash('Места и цена должны быть больше 0!', 'danger')
            return redirect(url_for('create_ride'))

        new_ride = Ride(
            departure=departure,
            destination=destination,
            date=date_str,
            time=time_str,
            seats=seats,
            price=price,
            driver_id=current_user.id
        )

        db.session.add(new_ride)
        db.session.commit()
        flash('Поездка создана!', 'success')
        return redirect(url_for('home'))

    return render_template('rides/create.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
