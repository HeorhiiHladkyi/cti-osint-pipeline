# CTI OSINT pipeline — reproducible run in a container (bonus: Docker).
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Mount your IoC list and collect artifacts to ./output on the host:
#   docker build -t cti-pipeline .
#   docker run --rm -v "${PWD}/output:/app/output" --env-file .env cti-pipeline -i examples/iocs.txt
ENTRYPOINT ["python", "run.py"]
CMD ["-i", "examples/iocs.txt"]
