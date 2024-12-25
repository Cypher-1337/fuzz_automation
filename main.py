# web_scanner.py
import os
import multiprocessing
import mysql.connector
import asyncio
from utils.color_print import ColorPrint
from utils.subdomain_utils import SubdomainUtils
from scanners.technology_detector import TechnologyDetector
from scanners.fuzzer import Fuzzer
from reporting.report_generator import ReportGenerator

class WebScanner:
    def __init__(self, db_config, output_dir):
        self.db_config = db_config
        self.output_dir = output_dir
        self.tech_detector = TechnologyDetector()
        self.fuzzer = Fuzzer(output_dir)
        self.report_generator = ReportGenerator(output_dir)

    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════╗
║             Web Fuzzing Tool              ║
║      Technology Detection & Directory     ║
║              Enumeration                  ║
╚═══════════════════════════════════════════╝
"""
        print(f"{banner}")

    def connect_db(self):
        try:
            return mysql.connector.connect(**self.db_config)
        except mysql.connector.Error as err:
            ColorPrint.error(f"Error connecting to database: {err}")
            raise

    def close_db(self, connection):
        if connection and connection.is_connected():
            connection.close()

    def get_subdomains_from_db(self, limit=10):
        conn = self.connect_db()
        cursor = conn.cursor()
        try:
            query = "SELECT alive FROM live WHERE fuzz < 2 ORDER BY id DESC LIMIT %s"  # Only get subdomains with fuzz < 2
            cursor.execute(query, (limit,))
            subdomains = [row[0] for row in cursor.fetchall()]
            return subdomains
        except mysql.connector.Error as err:
            ColorPrint.error(f"Error fetching subdomains from database: {err}")
            return []
        finally:
            cursor.close()
            self.close_db(conn)

    def update_fuzz_status(self, subdomain, status, directories_found=0):
        conn = self.connect_db()
        cursor = conn.cursor()
        try:
            query = "UPDATE live SET fuzz = %s, directories_found = %s WHERE alive = %s"
            cursor.execute(query, (status, directories_found, subdomain,))
            conn.commit()
            status_message = {
                1: f"Updated fuzz status for {subdomain} in the database with {directories_found} directories found.",
                5: f"Fuzzing for {subdomain} timed out (2 hours). Fuzz status updated to 5."
            }.get(status, f"Updated fuzz status for {subdomain} to {status}.")
            ColorPrint.info(status_message)
        except mysql.connector.Error as err:
            ColorPrint.error(f"Error updating fuzz status for {subdomain}: {err}")
        finally:
            cursor.close()
            self.close_db(conn)

    async def _run_fuzzer_with_timeout(self, subdomain, technology):
        try:
            async with asyncio.timeout(7200):  # 2 hours in seconds
                return self.fuzzer.fuzz_subdomain(subdomain, technology)
        except asyncio.TimeoutError:
            return None

    def process_subdomain(self, subdomain):
        """Processes a single subdomain (this will be run in parallel)."""
        ColorPrint.header(f"Processing {subdomain}")
        results = {}  # Initialize results for each subdomain

        try:
            # Detect technology
            technology, tech_details = self.tech_detector.detect_technology(subdomain)
            ColorPrint.info(f"Detected technology: {technology}")

            # Filter unwanted results
            if not SubdomainUtils.filter_unwanted_results(subdomain, tech_details):
                ColorPrint.warning(f"Skipping {subdomain} due to unwanted criteria.")
                self.update_fuzz_status(subdomain, 2) # Mark as skipped
                return  # Exit the function for this subdomain

            # Run fuzzing with timeout
            ColorPrint.header("Starting Directory Fuzzing")
            fuzz_results = asyncio.run(self._run_fuzzer_with_timeout(subdomain, technology))

            if fuzz_results is None:
                ColorPrint.warning(f"Fuzzing for {subdomain} timed out.")
                self.update_fuzz_status(subdomain, 5)
                return

            # Count all found resources (directories and files)
            directories_found_count = len(fuzz_results['results'])

            # Store results for the current subdomain
            results[subdomain] = {
                "technology": technology,
                "tech_details": tech_details,
                "fuzz_results": fuzz_results
            }

            # Generate report for the current subdomain
            self.report_generator.generate_report(subdomain, results)
            ColorPrint.success(f"Report generated for {subdomain}.")

            self.update_fuzz_status(subdomain, 1, directories_found_count) # Update with the count

        except KeyboardInterrupt:
            raise
        except Exception as e:
            ColorPrint.error(f"Error processing {subdomain}: {str(e)}")
            self.update_fuzz_status(subdomain, 3) # Mark as error
            return

        # Remove the report generation here as it's already done above
        # self.report_generator.generate_report(subdomain, results)
        # ColorPrint.success(f"Report generated for {subdomain}.")

    def run(self):
        try:
            self.print_banner()

            while True:
                # Step 1: Get the next batch of unfuzzed subdomains from the database
                live_subdomains = self.get_subdomains_from_db(limit=10)

                if not live_subdomains:
                    ColorPrint.info("No more subdomains to fuzz at the moment.")
                    break  # Exit the loop if no more subdomains are found

                ColorPrint.success(f"Found {len(live_subdomains)} subdomains to fuzz in this batch.")

                # Step 2: Process each subdomain in parallel
                with multiprocessing.Pool() as pool:
                    pool.map(self.process_subdomain, live_subdomains)

                ColorPrint.info("Finished processing the current batch of subdomains.")

            ColorPrint.success("Fuzzing completed for all available subdomains!")

        except KeyboardInterrupt:
            ColorPrint.warning("\nScanning interrupted by user.")
        except Exception as e:
            ColorPrint.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    # Database configuration
    db_config = {
        "host": "127.0.0.1",
        "user": "scanner",
        "password": "scanner",
        "database": "bugbounty"
    }
    scanner = WebScanner(db_config, "fuzzing_results")
    scanner.run()