# ML Model Server

This directory contains a Python-based server for performing machine learning-based audio processing.

## Plug and Play Architecture

The server is designed with a "plug and play" architecture that allows you to easily switch between different ML models. This is achieved by adhering to a simple API contract.

### API Contract

The server exposes a single endpoint for a specific audio processing task. For example, for voice activity detection (VAD), the endpoint is:

*   **Endpoint:** `/vad`
*   **Method:** `POST`
*   **Request Body:** A raw audio chunk.
*   **Response:** A JSON object with the results. For VAD, the response is `{'is_speech': true/false}`.

### How to Add a New Model

To add a new model, you need to:

1.  **Implement the model logic:** Create a new Python module that contains the code for your model.
2.  **Update `app.py`:** Modify the `app.py` file to use your new model. You can do this by:
    *   Importing your new model.
    *   Replacing the current model initialization with your new model.
    *   Updating the API endpoint logic to use your new model.

### Current Model

The current model is a simple Voice Activity Detector (VAD) based on the `webrtcvad` library. It is a lightweight and efficient model that is suitable for real-time applications.

### Future Models

You can replace the VAD with a more advanced model, such as a speaker diarization model from a library like `pyannote.audio`. To do this, you would need to:

1.  Install `pyannote.audio`.
2.  Update the `/vad` endpoint to return the speaker diarization results (e.g., `{'speaker_id': 'speaker_1'}`).
3.  Update the Go server to handle the new response format.
