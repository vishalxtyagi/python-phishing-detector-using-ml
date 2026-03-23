FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY ml/ ./ml/

# Copy model if it exists
COPY ml/model.pkl ./ml/model.pkl 2>/dev/null || true

EXPOSE 8000

ENV MODEL_PATH=/app/ml/model.pkl

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
