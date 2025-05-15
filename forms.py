from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

from flask_wtf import FlaskForm
from wtforms import StringField, DateField, TimeField, IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange
from datetime import datetime
from wtforms.validators import Email


class RideForm(FlaskForm):
    departure = StringField('Откуда', validators=[DataRequired()])
    destination = StringField('Куда', validators=[DataRequired()])
    date = DateField('Дата', validators=[DataRequired()], default=datetime.today)
    time = TimeField('Время', validators=[DataRequired()])
    seats_available = IntegerField('Количество мест', validators=[DataRequired()])
    seats = IntegerField('Места', validators=[
        DataRequired(),
        NumberRange(min=1, max=8, message="Должно быть от 1 до 8 мест")
    ])
    price = IntegerField('Цена (руб)', validators=[
        DataRequired(),
        NumberRange(min=0, message="Цена не может быть отрицательной")
    ])
    submit = SubmitField('Создать поездку')


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[
        DataRequired(),
        Length(min=4, max=20)
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message='Некорректный email адрес')
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(),
        Length(min=6)
    ])
    confirm_password = PasswordField('Подтвердите пароль', validators=[
        DataRequired(),
        EqualTo('password', message='Пароли должны совпадать')
    ])


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired("Поле обязательно для заполнения"),
        Email("Некорректный email адрес")
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired("Введите пароль")
    ])
    submit = SubmitField('Войти')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Сбросить пароль')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Новый пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Повторите пароль',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Изменить пароль')
