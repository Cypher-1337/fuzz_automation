from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init()

class ColorPrint:
    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}{Style.BRIGHT}[*]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}{Style.BRIGHT}[!]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def error(msg):
        print(f"{Fore.RED}{Style.BRIGHT}[-]{Style.RESET_ALL} {msg}")

    @staticmethod
    def header(msg):
        print(f"\n{Fore.BLUE}{Style.BRIGHT}{'=' * 60}")
        print(f"{msg.center(60)}")
        print(f"{'=' * 60}{Style.RESET_ALL}\n")