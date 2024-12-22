import requests
from .color_print import ColorPrint

class SubdomainUtils:
    @staticmethod
    def get_live_subdomains(file_path):
        """Filter live subdomains from a list."""
        live_subdomains = []
        try:
            with open(file_path, 'r') as file:
                subdomains = file.readlines()
            
            for subdomain in subdomains:
                subdomain = subdomain.strip()
                try:
                    live_subdomains.append(subdomain)
                except requests.RequestException:
                    continue

            return live_subdomains
        except Exception as e:
            ColorPrint.error(f"Error reading subdomains file: {str(e)}")
            return []

    @staticmethod
    def filter_unwanted_results(subdomain, tech_details):
        """Filter out subdomains that are not interesting based on certain criteria."""
        unwanted_keywords = ["static", "cdn", "images", "fonts"]
        domain = subdomain.split("//")[-1]

        # Filter based on keywords in the subdomain
        if any(keyword in domain for keyword in unwanted_keywords):
            return False

        # Filter based on WhatWeb or Wappalyzer results
        if "Cloudflare" in tech_details.get("WhatWeb", ""):
            return False

        return True