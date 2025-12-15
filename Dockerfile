FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
COPY app/ ./app/
RUN pip install --no-cache-dir -r requirements.txt
WORKDIR /app/app
ENV PYTHONUNBUFFERED=1
CMD ["python","-u", "app.py"]
