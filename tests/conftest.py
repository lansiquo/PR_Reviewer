from dotenv import load_dotenv
load_dotenv()  # ensures RUN_INTEGRATION / IT_* env are visible to pytest
import warnings

warnings.filterwarnings(
    "ignore",
    message=r"on_event is deprecated, use lifespan event handlers instead\.",
    category=DeprecationWarning,
    module=r"fastapi\..*",
)