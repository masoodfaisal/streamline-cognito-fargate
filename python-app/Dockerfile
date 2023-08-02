FROM python:3.10-bookworm

EXPOSE 8501

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

CMD streamlit run app.py --server.port 8501 --server.headless true  --server.enableCORS false --browser.serverAddress "0.0.0.0"
