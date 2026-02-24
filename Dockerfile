FROM python:3.11-slim
WORKDIR /app
COPY . .

RUN pip install -r requirements.txt
ENV PYTHONUNBUFFERED=1

EXPOSE 1080
CMD ["python", "proxy.py"]
