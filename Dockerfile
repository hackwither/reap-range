FROM python:3.12-slim

WORKDIR /app
COPY server.py .

EXPOSE 8080 8090

CMD ["python3", "server.py"]
