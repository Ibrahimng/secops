FROM python:3.11-slim

# Create isolated non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /home/appuser

# Install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app/ ./app/

# Switch to non-root user
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.server:app", "--host", "0.0.0.0", "--port", "8000"]
