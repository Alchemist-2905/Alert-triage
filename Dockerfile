FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8501 8080
# default: run the demo then serve the dashboard; override CMD for `live`
CMD ["sh", "-c", "python main.py demo && python main.py dashboard"]
