FROM python:3

RUN mkdir -p /app/curlpipe && \
    python3 -m pip install --upgrade pip

COPY . /app/curlpipe

RUN pip install -e /app/curlpipe

EXPOSE 5555

ENV SCRIPTS_DIR=/app/curlpipe/scripts

CMD [ "python3", "-m", "curlpipe" ]
