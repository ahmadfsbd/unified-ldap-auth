# syntax=docker/dockerfile:1
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for python-ldap
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libsasl2-dev \
        python3-dev \
        libldap2-dev \
        libssl-dev \
        build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY hgi-apps-auth.py ./

EXPOSE 9000

ENTRYPOINT ["python", "-u", "hgi-apps-auth.py"]
CMD ["--host", "0.0.0.0", "--port", "9000"]