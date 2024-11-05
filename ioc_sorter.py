import re
import sys
import os

def clean_ioc(ioc):
    ioc = re.sub(r'hxxp', 'http', ioc, flags=re.IGNORECASE)
    ioc = re.sub(r'\[|\]', '', ioc)
    ioc = re.sub(r',\s?(MD5|SHA-1|SHA-256|FQDN|URL|IP Address|SHA1|SHA256|SHA384|SHA512|RIPEMD-160|WHIRLPOOL|GOST|SHA3-256|SHA3-512)', '', ioc)
    return ioc.strip()

def is_ip(ioc):
    return re.match(r'\b\d{1,3}(\.\d{1,3}){3}\b', ioc)

def is_hash(ioc):
    return re.match(r'\b[0-9a-fA-F]{32,64}\b', ioc)

def is_url_or_domain(ioc):
    return re.search(r'^(http://|https://|www\.|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})(/[a-zA-Z0-9./-]*)?', ioc)

def is_cve(ioc):
    return re.match(r'CVE-\d{4}-\d{4,7}', ioc, re.IGNORECASE)

def is_email(ioc):
    return re.search(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', ioc)

def is_email_subject(line):
    return "Email Subject=" in line

def is_file_name(line):
    return re.search(r'\bFile Name=|\bFile Path=', line)

def process_file(filename, output_name):
    if not os.path.exists("result"):
        os.makedirs("result")

    with open(filename, 'r') as f:
        content = f.read().splitlines()

    urls_domains, emails, email_subjects, file_names, others, ips, hashes, cves, unknown_iocs = [], [], [], [], [], [], [], [], []
    created_files = []

    for line in content:
        ioc = clean_ioc(line.strip())
        if is_ip(ioc):
            ips.append(ioc)
        elif is_hash(ioc):
            hashes.append(ioc)
        elif is_url_or_domain(ioc):
            urls_domains.append(ioc)
        elif is_cve(ioc):
            cves.append(ioc)
        elif is_email(ioc):
            emails.append(ioc)
        elif is_email_subject(line):
            email_subjects.append(ioc)
        elif is_file_name(line):
            file_names.append(ioc)
        else:
            unknown_iocs.append(ioc)

    def save_to_file(iocs_list, file_type):
        if iocs_list:
            file_path = f'result/{file_type} IoCs - {output_name}.txt'
            with open(file_path, 'w') as f:
                f.write('\n'.join(iocs_list))
            created_files.append((file_path, len(iocs_list)))
        else:
            print(f"Alert: No {file_type} found")

    save_to_file(urls_domains, 'URLs')
    save_to_file(emails, 'Emails')
    save_to_file(email_subjects, 'Email Subjects')
    save_to_file(file_names, 'FileName')
    save_to_file(ips, 'IPs')
    save_to_file(hashes, 'Hashes')
    save_to_file(cves, 'CVEs')
    save_to_file(unknown_iocs, 'Others')

    total_iocs = sum(len(lst) for lst in [urls_domains, emails, email_subjects, file_names, ips, hashes, cves, unknown_iocs])
    print(f"\nTotal IoCs provided: {total_iocs}")
    print("Breakdown by type:")
    for file_path, count in created_files:
        print(f"- {file_path}: {count} items")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Please provide the filename as an argument")
    else:
        output_name = input("Enter a name to include in output files: ")
        process_file(sys.argv[1], output_name)