FROM python:slim-buster
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY app.py .
COPY templates templates
CMD ["python", "app.py"]

