FROM python:3.12-slim

RUN groupadd -r botuser && useradd -r -g botuser -s /bin/false botuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER botuser

CMD ["python", "bot.py"]
