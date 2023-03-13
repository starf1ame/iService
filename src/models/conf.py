from pathlib import Path
import yaml


def get():
    filename = Path(__file__).parent.parent.parent / \
        'db' / 'docker-compose.yml'
    with filename.open() as fp:
        return yaml.load(fp, Loader=yaml.FullLoader)
