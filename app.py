from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from forms import RegistrationForm, RideForm, LoginForm, ResetPasswordForm, ResetPasswordRequestForm
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'secret-key-123'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

bookings = db.Table('bookings',
                    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                    db.Column('ride_id', db.Integer, db.ForeignKey('ride.id'), primary_key=True),
                    db.Column('booking_time', db.DateTime, default=datetime.utcnow)
                    )


# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    booked_rides = db.relationship('Ride', secondary=bookings, backref='passengers', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Модель поездки
class Ride(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    departure = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seats_available = db.Column(db.Integer, nullable=False)


app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['SECURITY_PASSWORD_SALT'] = 'your-secret-salt'

mail = Mail(app)
ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = ResetPasswordRequestForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = ts.dumps(user.email, salt='password-reset-salt')
            msg = Message('Сброс пароля',
                          sender='noreply@yourdomain.com',
                          recipients=[user.email])
            msg.body = f'''Для сброса пароля перейдите по ссылке:
{url_for('reset_password_token', token=token, _external=True)}

Ссылка действительна 1 час.
'''
            mail.send(msg)

        flash('Проверьте ваш email для дальнейших инструкций', 'info')
        return redirect(url_for('login'))

    return render_template('auth/reset_request.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    try:
        email = ts.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('Недействительная или устаревшая ссылка', 'danger')
        return redirect(url_for('reset_password_request'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('reset_password_request'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Пароль успешно изменен!', 'success')
        return redirect(url_for('login'))

    return render_template('auth/reset_password.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    rides = Ride.query.all()
    return render_template('index.html', rides=rides)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()  # Создаем экземпляр формы

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('profile'))
        flash('Неверный email или пароль', 'danger')

    return render_template('auth/login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Создаем экземпляр формы

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
                password_hash=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация успешна! Войдите в аккаунт', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('auth/register.html', form=form)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/rides/create', methods=['GET', 'POST'])
@login_required
def create_ride():
    form = RideForm()

    if request.method == 'POST':
        departure = request.form['departure']
        destination = request.form['destination']
        date_str = request.form['date']
        time_str = request.form['time']
        seats_available = int(request.form['seats_available'])
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

        if seats_available <= 0 or price <= 0:
            flash('Места и цена должны быть больше 0!', 'danger')
            return redirect(url_for('create_ride'))

        new_ride = Ride(
            departure=departure,
            destination=destination,
            date=date_str,
            time=time_str,
            seats_available=form.seats_available.data,
            price=price,
            driver_id=current_user.id
        )

        db.session.add(new_ride)
        db.session.commit()
        flash('Поездка создана!', 'success')
        return redirect(url_for('home'))

    return render_template('rides/create.html', form=form,
                           now=datetime.now().strftime('%Y-%m-%d'))


@app.route('/rides/book/<int:ride_id>', methods=['POST'])
@login_required
def book_ride(ride_id):
    ride = Ride.query.get_or_404(ride_id)

    if current_user in ride.passengers:
        flash('Вы уже забронировали эту поездку!', 'warning')
        return redirect(url_for('home'))

    if ride.seats_available <= 0:
        flash('Нет свободных мест!', 'danger')
        return redirect(url_for('home'))

    # Добавляем бронирование
    ride.passengers.append(current_user)
    ride.seats_available -= 1
    db.session.commit()

    flash('Поездка успешно забронирована!', 'success')
    return redirect(url_for('profile'))


@app.route('/cancel_booking/<int:ride_id>', methods=['POST'])
@login_required
def cancel_booking(ride_id):
    ride = Ride.query.get_or_404(ride_id)

    if current_user not in ride.passengers:
        flash('У вас нет брони на эту поездку!', 'warning')
        return redirect(url_for('profile'))

    if datetime.strptime(f"{ride.date} {ride.time}", "%Y-%m-%d %H:%M") < datetime.now():
        flash('Невозможно отменить завершенную поездку!', 'danger')
        return redirect(url_for('profile'))

    try:
        # Удаляем бронирование
        ride.passengers.remove(current_user)
        ride.seats_available += 1
        db.session.commit()
        flash('Бронирование успешно отменено!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при отмене бронирования', 'danger')

    return redirect(url_for('profile'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
