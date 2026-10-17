# Python 3.12 — сознательный выбор: стабильная версия, для которой у всех
# зависимостей (включая pydantic-core) давно есть готовые wheels. Это
# полностью снимает проблему сборки Rust-расширений под очень свежий
# Python (см. QUICKSTART.md — с этим столкнулись при установке на голом
# хосте с Python 3.14).
FROM python:3.12-slim

WORKDIR /app

# Системные пакеты не нужны — все наши зависимости имеют готовые wheels
# под эту версию Python (fpdf2 и pyjwt — чистый Python, остальное с wheels).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
