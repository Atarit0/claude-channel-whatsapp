#!/usr/bin/env python3
"""Transcribe an audio file (OGG/WAV/MP3) using Vosk.

Usage: transcribe.py <audio-path> [--lang es|ca]
Prints transcript to stdout. Silent VOSK logs redirected to stderr.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import wave

MODELS = {
    "es": "/usr/local/share/vosk-models/vosk-model-small-es-0.42",
    "ca": "/usr/local/share/vosk-models/vosk-model-small-ca-0.4",
}


def to_wav(src: str) -> str:
    fd, dst = tempfile.mkstemp(suffix=".wav", prefix="wa_stt_")
    os.close(fd)
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-i", src,
         "-ar", "16000", "-ac", "1", dst],
        check=True,
    )
    return dst


def transcribe(wav_path: str, model_path: str) -> str:
    from vosk import Model, KaldiRecognizer  # imported late so --help is instant
    model = Model(model_path)
    wf = wave.open(wav_path, "rb")
    rec = KaldiRecognizer(model, wf.getframerate())
    out = []
    while True:
        data = wf.readframes(4000)
        if not data:
            break
        if rec.AcceptWaveform(data):
            out.append(json.loads(rec.Result()).get("text", ""))
    out.append(json.loads(rec.FinalResult()).get("text", ""))
    return " ".join(t for t in out if t).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("audio")
    ap.add_argument("--lang", default="es", choices=list(MODELS.keys()))
    args = ap.parse_args()

    # Silence Vosk's chatty logger on stderr from stdout
    os.environ["VOSK_LOG_LEVEL"] = "-1"

    try:
        wav = to_wav(args.audio)
        try:
            text = transcribe(wav, MODELS[args.lang])
        finally:
            try:
                os.unlink(wav)
            except OSError:
                pass
        print(text)
    except Exception as e:
        print(f"[transcribe error] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
