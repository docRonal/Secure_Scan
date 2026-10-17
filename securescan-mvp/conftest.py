"""Configure the test environment before application settings are imported."""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-deployment")
