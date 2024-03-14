from settings import settings as env


class Config:
    SQLALCHEMY_DATABASE_URI = f'postgresql+psycopg2://{env.USER}:{env.PASSWORD}@{env.HOST}:{env.PORT}/{env.DB}'
