import pytest

from alert_triage import pipeline as P
from alert_triage.config import load_config
from alert_triage.data_gen import generate_dataset


@pytest.fixture(scope="session")
def cfg():
    return load_config()


@pytest.fixture(scope="session")
def data():
    return generate_dataset(9000, seed=7, days=1)


@pytest.fixture(scope="session")
def bundle(data, cfg):
    return P.train(data.iloc[: int(len(data) * 0.7)], cfg)


@pytest.fixture(scope="session")
def test_df(data):
    return data.iloc[int(len(data) * 0.7):].reset_index(drop=True)
