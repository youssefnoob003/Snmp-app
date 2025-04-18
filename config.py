import os

class Config:
    # URI for the main database (devices.db)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///devices.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Path to models.db located inside the 'app/' directory
    from pathlib import Path

    BASE_DIR = Path(__file__).resolve().parent
    MODELS_DATABASE_URI = f"sqlite:///{(BASE_DIR / 'models.db').as_posix()}"

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
