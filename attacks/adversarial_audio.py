# speech_attack_sim/attacks/adversarial_audio.py
from edge_tts import Communicate
import asyncio
import os

async def synthesize_audio(text, voice="en-US-JennyNeural", output_dir="data/outputs"):
    # Synthesizes speech audio from text using Edge TTS and saves to file
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{hash(text)}.mp3")
    communicate = Communicate(text, voice)
    await communicate.save(file_path)
    return file_path

# Wrapper for sync use
def generate_adversarial_audio(text, voice="en-US-JennyNeural"):
    # Synchronously generates adversarial audio from text using synthesize_audio
    return asyncio.run(synthesize_audio(text, voice))
