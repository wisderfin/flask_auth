FROM python:3.12-alpine

WORKDIR /app

COPY poetry/poetry.lock poetry/pyproject.toml ./

RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi


COPY . .