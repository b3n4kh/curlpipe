FROM python:3

COPY curlpipe /app/
COPY scripts /app/

RUN pip install -e /app/curlpipe

EXPOSE 5555

CMD [ "python3", "-m", "curlpipe" ]
