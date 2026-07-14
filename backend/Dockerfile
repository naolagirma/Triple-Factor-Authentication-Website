FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# start flask on 0.0.0.0 so it's reachable from other containers
# we do it this way instead of editing app.py
CMD ["python", "-c", "from app import app; app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)"]
