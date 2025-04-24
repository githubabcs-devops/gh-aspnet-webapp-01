FROM python:3.7-alpine

ARG user=python
ARG home=/home/$user

RUN adduser \
    --disabled-password \
    --home $home \
    $user

WORKDIR /myapp
ENV PYTHONPATH "${PYTHONPATH}:/myapp"

COPY server .

RUN python3 -m pip install pipenv && \
    python3 -m pipenv install --system

CMD ["python", "-m", "myapp"]

