from urllib.parse import urlparse, urlunparse

class URLHelper:
    @staticmethod
    def normalize_url(url: str) -> tuple[str, str]:
        """
        Normalize a URL and return both the full URL and domain.
        
        Args:
            url: The URL or domain to normalize
            
        Returns:
            tuple: (full_url, domain)
            
        Example:
            'example.com' -> ('https://example.com', 'example.com')
            'http://example.com' -> ('http://example.com', 'example.com')
            'https://www.example.com' -> ('https://www.example.com', 'example.com')
        """
        # Remove any whitespace
        url = url.strip()
        
        # Parse the URL
        parsed = urlparse(url)
        
        # If no scheme is provided, add https://
        if not parsed.scheme:
            parsed = urlparse(f"https://{url}")
        
        # Get the domain (remove www. if present)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Reconstruct the full URL
        full_url = urlunparse(parsed)
        
        return full_url, domain 