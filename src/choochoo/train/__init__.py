from choochoo.train.base import TrainClient
from choochoo.train.fake import FakeTrain

__all__ = ["TrainClient", "FakeTrain", "build_train"]


def build_train(kind: str, train_id: str) -> TrainClient:
    """Factory. `kind` comes from the CHOOCHOO_TRAIN env var."""
    if kind == "fake":
        return FakeTrain(train_id)
    if kind == "powered_up":
        from choochoo.train.powered_up import PoweredUpTrain

        return PoweredUpTrain(train_id)
    if kind == "buwizz":
        from choochoo.train.buwizz import BuWizzTrain

        return BuWizzTrain(train_id)
    raise ValueError(f"Unknown train kind: {kind!r}")
