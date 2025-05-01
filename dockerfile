FROM python:3.13-slim

RUN apt-get update && apt-get install -y \
    python3-tk \
    tk-dev \
    libx11-6 \
    x11-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /SecMac

# Copy the current directory contents into the container
COPY . .

# Install any needed dependencies specified in requirements.txt
# If you don't have a requirements.txt file, you should create one
RUN pip install --no-cache-dir -r requirements.txt

# Expose default port
EXPOSE 12345

ENV NAME=SecChat

CMD ["python", "secure_chat.py"]