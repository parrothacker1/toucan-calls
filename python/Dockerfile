FROM python:3.13-slim

WORKDIR /app

# Install system dependencies and uv
RUN apt-get update && apt-get install -y --no-install-recommends libsndfile1 git && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir uv

# Copy and install Python dependencies
COPY requirements.txt .
RUN uv pip install --system -r requirements.txt

# Copy the model files
COPY 3dspeaker_speech_eres2net_sv_en_voxceleb_16k.onnx .
COPY sherpa-onnx-pyannote-segmentation-3-0/ ./sherpa-onnx-pyannote-segmentation-3-0/

# Copy the application code
COPY app.py .

EXPOSE 5001

CMD ["python", "app.py"]
