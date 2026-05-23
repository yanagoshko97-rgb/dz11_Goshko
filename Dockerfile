FROM python:3.11-slim

WORKDIR /app

COPY app/app.py /app/app.py
COPY app/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "/app/app.py"]