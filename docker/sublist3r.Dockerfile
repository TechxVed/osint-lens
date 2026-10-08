FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r

WORKDIR /opt/Sublist3r

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "sublist3r.py"]
