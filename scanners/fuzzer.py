import os
import subprocess
import json
from utils.color_print import ColorPrint
import random

class Fuzzer:
    def __init__(self, output_dir="/home/kali/fuzz"):
        self.output_dir = output_dir
        self.wordlists = {
            "php": "/home/kali/Desktop/wordlist/php/php.txt",
            "jsp": "/home/kali/Desktop/wordlist/jsp/jsp.txt",
            "nodejs": "/home/kali/Desktop/wordlist/nodejs/node.txt",
            "wordpress": "/home/kali/Desktop/wordlist/wordpress/wordpress.txt",
            # "react": "/home/kali/Desktop/wordlist/react/react.txt",
            "nextjs": "/home/kali/Desktop/wordlist/nextjs/nextjs.txt",
            "ruby": "/home/kali/Desktop/wordlist/ruby/ruby.txt",
            "python": "/home/kali/Desktop/wordlist/python/python.txt",
            "general": "/home/kali/Desktop/wordlist/common.txt",
        }
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
            # Add more user agents as needed
        ]

    def fuzz_subdomain(self, subdomain, technology):
        """Run FFUF on a subdomain with the appropriate wordlist and return results."""
        wordlist = self._select_wordlist(technology)
        domain = subdomain.split("//")[-1].split("/")[0]
        sanitized_subdomain = domain.replace('.', '')
        output_file = os.path.join(self.output_dir, f"{sanitized_subdomain}_ffuf.json")
        user_agent = random.choice(self.user_agents)

        os.makedirs(self.output_dir, exist_ok=True)

        ffuf_command = [
            "ffuf",
            "-u", f"{subdomain}/FUZZ",
            "-w", wordlist,
            "-ac",
            "-o", output_file,
            "-of", "json",
            "-H", f"User-Agent: {user_agent}"
        ]

        try:
            subprocess.run(ffuf_command, text=True, check=True)

            with open(output_file, 'r') as f:
                results = json.load(f)

            os.remove(output_file)
            ColorPrint.success(f"Fuzzing complete for {subdomain}. Results saved to {output_file}.")
            return results
        except subprocess.CalledProcessError as e:
            ColorPrint.error(f"Error fuzzing {subdomain}: FFUF exited with code {e.returncode}")
            ColorPrint.error(f"FFUF Output:\n{e.stderr}")
            return None
        except FileNotFoundError:
            ColorPrint.error(f"Error fuzzing {subdomain}: FFUF execution failed, is ffuf installed?")
            return None
        except json.JSONDecodeError:
            ColorPrint.error(f"Error parsing FFUF output for {subdomain}.")
            return None
        except Exception as e:
            ColorPrint.error(f"Error fuzzing {subdomain}: {e}")
            return None

    def _select_wordlist(self, technology):
        """Select the appropriate wordlist based on the technology."""
        return self.wordlists.get(technology, self.wordlists["general"])