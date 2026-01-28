from alpine:3.23.3
RUN apk add python3 py3-flask py3-requests py3-waitress py3-paramiko
COPY --chmod=755 server.py /app/server.py
COPY --chmod=700 config.sample.json /app/config.json
CMD cd /app&&python /app/server.py