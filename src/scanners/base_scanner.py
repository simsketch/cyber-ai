from abc import ABC, abstractmethod

class BaseScanner(ABC):
    """Base class for all scanners"""
    
    def __init__(self, target: str):
        """Initialize scanner with target"""
        self.target = target
        self.results = {}

    @abstractmethod
    async def scan(self) -> dict:
        """
        Perform the scan operation
        Returns:
            dict: Scan results
        """
        pass

    def get_results(self) -> dict:
        """
        Get the scan results
        Returns:
            dict: Scan results
        """
        return self.results 