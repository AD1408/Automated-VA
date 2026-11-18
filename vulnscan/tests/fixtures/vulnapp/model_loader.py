import pickle

import torch
from transformers import AutoModel


def load():
    model = AutoModel.from_pretrained("someone/custom-model", trust_remote_code=True)
    weights = torch.load("weights.pt")
    with open("index.pkl", "rb") as fh:
        index = pickle.load(fh)
    return model, weights, index
