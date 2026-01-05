# providers/base.py
from abc import ABC, abstractmethod

class BaseProvider(ABC):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = ""

    @abstractmethod
    def fetch(self, ioc: str, ioc_type: str):
        """
        Este método deve ser implementado por cada provider específico.
        Ele será responsável por ir até a API e trazer os dados.
        """
        pass