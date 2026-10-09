FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/pdscan
COPY dist/pdscan-*.whl /tmp/wheels/
RUN pip install --no-cache-dir --no-index /tmp/wheels/*.whl && rm -rf /tmp/wheels && useradd --uid 10001 --create-home scanner
USER 10001:10001
WORKDIR /reports
ENTRYPOINT ["pdscan"]
CMD ["--help"]
