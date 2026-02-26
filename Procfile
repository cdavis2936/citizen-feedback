web: if [ -d backend ]; then cd backend; fi; gunicorn app:app -k gthread --threads 4 -w 1 --bind 0.0.0.0:$PORT
