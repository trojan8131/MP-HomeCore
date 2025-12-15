FROM python:3.12-slim
WORKDIR /app

# Kopiujemy tylko kod aplikacji i plik requirements
COPY requirements.txt .
COPY app/ ./app/

# Instalujemy zależności
RUN pip install --no-cache-dir -r requirements.txt

# Ustawiamy katalog roboczy na /app/app
WORKDIR /app/app
ENV PYTHONUNBUFFERED=1

# Domyślne uruchomienie z parametrem -d
CMD ["python","-u", "app.py"]
