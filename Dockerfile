FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY backend ./backend
COPY web ./web
RUN pip install --no-cache-dir .
EXPOSE 8080
ENV HYDRASHIELD_WEB_ROOT=/app/web
CMD ["python", "-m", "hydrashield.api", "--host", "0.0.0.0", "--port", "8080", "--demo"]
