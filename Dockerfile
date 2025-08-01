# Use official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the app with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]

