FROM python:3.12-slim

WORKDIR /code

COPY requirements-deploy.txt .
RUN pip install --no-cache-dir -r requirements-deploy.txt

COPY . .

ENV NEO4J_URI=bolt://localhost:7687
ENV NEO4J_USER=neo4j
ENV NEO4J_PASSWORD=vulngraph123
ENV OLLAMA_URL=http://localhost:11434
ENV OLLAMA_MODEL=llama3.2:3b
ENV DISABLE_RAG=true

EXPOSE 7860

CMD ["streamlit", "run", "app/main.py", "--server.port=7860", "--server.address=0.0.0.0", "--server.headless=true"]