FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests

COPY client_ring.py ./client_ring.py

EXPOSE 8100

ENV ENABLE_GUI=false

CMD ["python", "client_ring.py"]
