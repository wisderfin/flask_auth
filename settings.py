from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    HOST: str
    PORT: str
    DB: str
    USER: str
    PASSWORD: str
    KEY: str
    BCRYPT_LOG_ROUNDS: int

    class Config:
        env_file = ".env"


settings = Settings()