import logging
import os

import uvicorn

from .app import create_app


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    uvicorn.run(create_app(), host="127.0.0.1", port=int(os.getenv("WORDSHIELD_PORT", "8844")), access_log=False)


if __name__ == "__main__":
    main()
