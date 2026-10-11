"""MailHunterPro - CLI Tool"""
import argparse
import os
import sys
import json
import email
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import MailHunterConfig
from core.database import MailHunterDB
from core.parser import EmailParser
from core.security_analyzer import SecurityAnalyzer
from core.header_analyzer import HeaderAnalyzer
from core.url_reputation import URLReputation
from core.ioc_extractor import IOCExtractor
from core.brand_detector import BrandDetector
from core.report_generator import ReportGenerator
from core.batch_analyzer import BatchAnalyzer

def main():
    parser = argparse.ArgumentParser(
        description='MailHunterPro — Advanced Email Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze suspicious.eml
  %(prog)s batch ./emails/ --format html
  %(prog)s analyze suspicious.eml --vt-key YOUR_KEY
  %(prog)s batch ./emails/ --json-output results.json
        """
    )
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    analyze_parser = subparsers.add_parser('analyze', help='Analyze a single .eml file')
    analyze_parser.add_argument('file', help='Path to .eml file')
    analyze_parser.add_argument('--vt-key', help='VirusTotal API key')
    analyze_parser.add_argument('--output-dir', '-o', help='Output directory for reports')
    analyze_parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', help='Report format')

    batch_parser = subparsers.add_parser('batch', help='Batch analyze all .eml files in a directory')
    batch_parser.add_argument('directory', help='Directory containing .eml files')
    batch_parser.add_argument('--vt-key', help='VirusTotal API key')
    batch_parser.add_argument('--output-dir', '-o', help='Output directory for reports')
    batch_parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', help='Report format')
    batch_parser.add_argument('--json-output', help='Save summary to JSON file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    config = MailHunterConfig()
    db = MailHunterDB()
    eml_parser = EmailParser()
    security_analyzer = SecurityAnalyzer(config, db)
    header_analyzer = HeaderAnalyzer()
    ioc_extractor = IOCExtractor()
    brand_detector = BrandDetector()
    vt_key = args.vt_key or config.get_api_key('virustotal')
    url_reputation = URLReputation(vt_key=vt_key)
    output_dir = args.output_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'reports')
    report_generator = ReportGenerator(output_dir=output_dir)

    batch_analyzer = BatchAnalyzer(
        eml_parser, security_analyzer, header_analyzer,
        ioc_extractor, brand_detector, report_generator, url_reputation
    )

    if args.command == 'analyze':
        result = batch_analyzer.analyze_file(args.file)
        if not result:
            print(f"Failed to analyze {args.file}")
            sys.exit(1)

        print(f"\n{'='*60}")
        print(f"MailHunterPro Analysis Report")
        print(f"{'='*60}")
        print(f"File: {args.file}")
        print(f"Score: {result['score']}/100")
        print(f"Verdict: {result['verdict']}")
        print(f"Flags: {', '.join(result['flags']) if result['flags'] else 'None'}")

        if result['header_findings']:
            print(f"\nAuthentication Findings:")
            for f in result['header_findings']:
                print(f"  [{f['weight']:+d}] {f['type']}: {f['detail']}")

        if result['brand_findings']:
            print(f"\nBrand Impersonation:")
            for f in result['brand_findings']:
                print(f"  [{f['weight']:+d}] {f['brand']}: {f['detail']}")

        iocs = result.get('iocs', {})
        if iocs.get('defanged'):
            print(f"\nExtracted IOCs:")
            for ioc in iocs['defanged']:
                print(f"  {ioc['type']}: {ioc['defanged']}")

        print(f"\nReports:")
        print(f"  JSON: {result['report_json']}")
        print(f"  HTML: {result['report_html']}")
        print(f"{'='*60}\n")

    elif args.command == 'batch':
        if not os.path.isdir(args.directory):
            print(f"Directory not found: {args.directory}")
            sys.exit(1)

        print(f"Scanning directory: {args.directory}")
        results = batch_analyzer.analyze_directory(args.directory)
        summary = batch_analyzer.generate_summary(results)

        print(f"\n{'='*60}")
        print(f"Batch Analysis Summary")
        print(f"{'='*60}")
        print(f"Total files: {summary['total']}")
        print(f"Malicious: {summary['malicious']} ({summary['malicious_pct']}%)")
        print(f"Suspicious: {summary['suspicious']}")
        print(f"Clean: {summary['clean']}")
        print(f"Average score: {summary['average_score']}")
        print(f"Highest score: {summary['highest_score']}")

        if summary['top_flags']:
            print(f"\nTop Flags:")
            for item in summary['top_flags']:
                print(f"  {item['flag']}: {item['count']}x")

        print(f"\nIndividual Results:")
        for r in results:
            flag_str = ', '.join(r['flags'][:3]) if r['flags'] else 'None'
            print(f"  [{r['score']:3d}] {r['verdict']:8s} | {os.path.basename(r['file']):40s} | {flag_str}")

        if args.json_output:
            with open(args.json_output, 'w') as f:
                json.dump({'summary': summary, 'results': [
                    {'file': os.path.basename(r['file']), 'score': r['score'], 'verdict': r['verdict'], 'flags': r['flags']}
                    for r in results
                ]}, f, indent=2, default=str)
            print(f"\nSummary saved to: {args.json_output}")

        print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
