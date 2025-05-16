# Use an official lightweight Python image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies (for pymysql)
RUN apt-get update && apt-get install -y gcc libmariadb-dev && apt-get clean

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your application code into the container
COPY . .

# Set environment variable to avoid Python buffering output
ENV PYTHONUNBUFFERED=1

# Expose the port your Flask app runs on
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
