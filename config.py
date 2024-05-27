from os import environ, path
from dotenv import load_dotenv

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'), override=True)

class Config:
    """Base config."""
    SECRET_KEY = environ.get('SECRET_KEY')
    SESSION_COOKIE_NAME = environ.get('SESSION_COOKIE_NAME')

    SQLALCHEMY_DATABASE_URI = environ.get('SQLALCHEMY_DATABASE_URI')
    if SQLALCHEMY_DATABASE_URI is None or SQLALCHEMY_DATABASE_URI == "":
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + path.join(basedir, environ.get('SQLITE_FILE_RELATIVE_PATH'))

    SQLALCHEMY_ECHO = environ.get('SQLALCHEMY_ECHO')

    MAIL_SUBJECT_PREFIX = environ.get('MAIL_SUBJECT_PREFIX')
    MAIL_SENDER_NAME = environ.get('MAIL_SENDER_NAME')
    MAIL_SENDER_ADDR = environ.get('MAIL_SENDER_ADDR')
    MAIL_SENDER_PASSWORD = environ.get('MAIL_SENDER_PASSWORD')
    MAIL_SMTP_SERVER = environ.get('MAIL_SMTP_SERVER')
    MAIL_SMTP_PORT = int(environ.get('MAIL_SMTP_PORT'))

    EXTERNAL_URL = environ.get('EXTERNAL_URL')
    DEBUG_TB_INTERCEPT_REDIRECTS = environ.get('DEBUG_TB_INTERCEPT_REDIRECTS', False)

    # Agrega las configuraciones para Flask-Mail
    MAIL_SERVER = MAIL_SMTP_SERVER
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = MAIL_SENDER_ADDR
    MAIL_PASSWORD = MAIL_SENDER_PASSWORD
    MAIL_DEFAULT_SENDER = MAIL_SENDER_ADDR

    # Configuración para el token de un solo uso
    ONE_TIME_TOKEN_EXPIRATION = int(environ.get('ONE_TIME_TOKEN_EXPIRATION', 3600))
