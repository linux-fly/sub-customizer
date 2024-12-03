from fastapi.templating import Jinja2Templates

from .config import settings

templates = Jinja2Templates(directory=settings.api_dir / "templates")
