"""CSV -> figures (results/figures/*.png)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.visualization import make_all  # noqa: E402

if __name__ == "__main__":
    make_all()
    print("figures written")
