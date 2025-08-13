import csv
from src.colors import Colors


def save_to_csv(data, header, filename="successful_credentials.csv"):
    if not data:
        return
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header)
            writer.writerows(data)
        print(f"{Colors.s} Saved {len(data)} row(s) to '{filename}'")
    except Exception as e:
        print(f"{Colors.e} Failed to save data: {e}")

def save_results(successful_creds, success_count,header):

    if success_count > 0:
        choice = input("Do you want to save the results? (y/n): ").strip().lower()
        if choice == "y":
            print(f"{Colors.s} Saving {success_count} successful credentials to CSV...")
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"results_{timestamp}.csv"
            save_to_csv(successful_creds, header, filename)
        else:
            print(f"{Colors.w} Results were not saved.")
            return

