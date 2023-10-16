from decouple import config
import os

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

class Config:
    SECRET_KEY = config("SECRET_KEY")
    SQLALCHEMY_TRACK_MODIFICATIONs=config('SQLALCHEMY_TRACK_MODIFICATIONS',cast=bool)

class DevConfig(Config):
    SQLALCHEMY_DATABASE_URI ="sqlite:///"+os.path.join(BASE_DIR, 'user-authentication.db')
    DEBUG=True
    SQLALCHEMY_ECHO = True