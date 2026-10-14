import csv
import json
import os
from datetime import datetime


class DataExporter:
    def __init__(self, database, export_dir="data/export"):
        self.database = database
        self.export_dir = export_dir
        os.makedirs(export_dir, exist_ok=True)

    def export_to_csv(self, threshold=0, filename=None):
        if not filename:
            filename = f"mailhunter_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        filepath = os.path.join(self.export_dir, filename)
        results = self.database.get_suspicious_emails(threshold)

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Sender', 'Subject', 'Score', 'Scan Date', 'Flags'])
            for row in results:
                writer.writerow(row)

        return filepath

    def export_to_json(self, threshold=0, filename=None):
        if not filename:
            filename = f"mailhunter_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        filepath = os.path.join(self.export_dir, filename)
        results = self.database.get_suspicious_emails(threshold)

        data = []
        for row in results:
            email_id, sender, subject, score, scan_date, flags = row
            data.append({
                'id': email_id,
                'sender': sender,
                'subject': subject,
                'score': score,
                'scan_date': scan_date,
                'flags': flags
            })

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return filepath

    def export_statistics(self, filename=None):
        if not filename:
            filename = f"mailhunter_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        filepath = os.path.join(self.export_dir, filename)
        stats = self.database.get_statistics()
        stats['export_date'] = datetime.now().isoformat()

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)

        return filepath
