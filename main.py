"""
main.py

The single entry point. Loads .env (so SHODAN_API_KEY etc. are available
via os.getenv before any plugin runs), then hands off to the Typer app
defined in cli/commands.py.

Run with: python main.py <command> [options]
"""

from dotenv import load_dotenv

load_dotenv()  # populates os.environ from a local .env file, if present

from cli.commands import app  # noqa: E402 - must come after load_dotenv()

if __name__ == "__main__":
    app()
