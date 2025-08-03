import requests
import os
import sys
import json
import zipfile
import fnmatch
import xml.etree.ElementTree as ET
import time
import shutil
import tempfile
import argparse
import traceback
import pandas as pd
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCA_account = 'SCA_account'
SCA_username = 'SCA_user'
SCA_password = 'SCA_password'
SCA_url = 'https://eu.sca.checkmarx.net'
SCA_api_url = 'https://eu.api-sca.checkmarx.net'
SCA_auth_url = 'https://eu.platform.checkmarx.net/identity/connect/token'
SCA_high_threshold = 5
# SCA_high_threshold = -1 # do not wait for scan
package_exclude_json = './excluded-packages.json'
SCA_proxy = ''
proxy_servers = {
   'https': SCA_proxy
}

# Global exclude package list
EXCLUDE_PACKAGES = [
    # Format: {"package": "package-name", "version": "version-to-exclude"}
    # If version is empty, all versions of the package will be excluded
     {"package": "local2", "version": ""},
     {"package": "local3", "version": ""}
]

# Global setting for removing dev dependencies
REMOVE_DEV_DEPENDENCIES = True

# Global setting for not breaking builds even if vulnerabilities / license issue exist
SHOW_RESULTS_DO_NOT_BREAK_BUILD = False

# Global setting for breaking build only on direct vulnerabilities
BREAK_ONLY_FOR_DIRECT = False
# BREAK_ONLY_FOR_DIRECT = True

# Gobal setting for minimum risk score threshold (default: None means no risk score filtering)
# If set to a number, build will only break if at least one vulnerability has a risk score higher than this threshold
# RISK_SCORE_THRESHOLD = None
RISK_SCORE_THRESHOLD = 9.0

# Define a global list of restricted licenses
RESTRICTED_LICENSES = ["AGPL"]  # You can extend this list as needed
# RESTRICTED_LICENSES = ["AGPL", "Apache 2.0"]  # You can extend this list as needed

# Define the patterns to include in the zip file
manifest_patterns = ['package.json', 'packages.config', '*.csproj', 'requirements.txt', 'pom.xml', 'composer.json', 'Directory.Packages.props']

# Load exclude packages from JSON file if it exists
def load_exclude_packages(exclude_file):
    global EXCLUDE_PACKAGES
    try:
        if os.path.exists(exclude_file):
            with open(exclude_file, 'r') as f:
                EXCLUDE_PACKAGES = json.load(f)
                print(f"Loaded {len(EXCLUDE_PACKAGES)} packages to exclude")
    except Exception as e:
        print(f"Error loading exclude packages: {e}")

def parse_risk_score(risk_score_value):
    """
    Parse risk score value and return a float or None if invalid/N/A
    """
    if risk_score_value is None or str(risk_score_value).upper() in ['N/A', 'NAN', '']:
        return None
    
    try:
        return float(risk_score_value)
    except (ValueError, TypeError):
        return None

def SCA_get_access_token():
    try:
        payload = {
            'username': SCA_username,
            'password': SCA_password,
            'acr_values': 'Tenant:' + SCA_account,
            'scope': 'sca_api',
            'client_id': 'sca_resource_owner',
            'grant_type': 'password'
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(SCA_auth_url, headers=headers, data=payload, verify=False, proxies=proxy_servers)

#        print('SCA_get_access_token - token = ' + response.text)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        access_token = response.json()['access_token']
        return access_token
    except requests.RequestException as e:
        print("Exception: Failed to get access token:", str(e))
        return ""

def SCA_create_project(project_name, access_token="", team_name=None):
    if(not access_token):
        access_token = SCA_get_access_token()

    url = SCA_api_url + "/risk-management/projects"

    try:
        payload = json.dumps({
        "name": project_name,
        "assignedTeams": [f"/CxServer/{team_name}"] if team_name else [],
        })
        headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
        }

        response = requests.request("POST", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        project_id = response_json['id']  # Assuming the first project with the given name is returned
    except Exception as e:
        print("Exception: SCA_create_project:", str(e))
        return ""
    else:
        print('SCA_create_project - project_name= ' + response.text)
        return project_id
    
def SCA_get_project_id(project_name, access_token=""):
    if(not access_token):
        access_token = SCA_get_access_token()

    url = f"{SCA_api_url}/risk-management/projects?name={project_name}"

    try:
        headers = {
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.get(url, headers=headers, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        project_id = response_json['id']  # Assuming the first project with the given name is returned
    except requests.RequestException as e:
        print("Exception: Failed to get project ID:", str(e))
        return ""
    except (KeyError, IndexError):
        print("Exception: Project ID not found")
        return ""
    else:
        # print('SCA_get_project_id id:', project_id)
        return project_id

def SCA_get_project_latest_scan_id(project_name, access_token=""):
    if(not access_token):
        access_token = SCA_get_access_token()

    url = SCA_api_url + "/risk-management/projects?name=" + project_name

    try:
        payload = {}
        headers = {
        'Authorization': 'Bearer ' + access_token
        }

        response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
        response_json = response.json()
    except Exception as e:
        print("Exception: SCA_get_project_latest_scan_id:", str(e))
        return ""
    else:
        try:
        #    print('SCA_get_project_latest_scan_id scan_id= ' + response_json['latestScanId'])
            return response_json['latestScanId']
        except Exception as e:
            return ""

def SCA_get_upload_link(project_id, access_token):
    if(not access_token):
        access_token = SCA_get_access_token()
    
    url = f"{SCA_api_url}/api/uploads"

    try:
        payload = {
            "projectId": project_id
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.post(url, headers=headers, json=payload, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        upload_url = response_json.get('url')
    except requests.RequestException as e:
        print("Exception: Failed to get upload link:", str(e))
        return ""
    except KeyError:
        print("Exception: 'uploadUrl' key not found in response")
        return ""
    else:
        return upload_url

def SCA_upload_file(upload_link, zip_file_path, access_token=""):
    if(not access_token):
        access_token = SCA_get_access_token()

    try:
        with open(zip_file_path, 'rb') as file:
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-zip-compressed',
                'Authorization': 'Bearer ' + access_token
            }
            response = requests.put(upload_link, headers=headers, data=file, proxies=proxy_servers, verify=False)
            response.raise_for_status()  # Raise an error for bad responses
            # print('SCA_upload_file:', response.text)
    except requests.RequestException as e:
        print("Exception: Failed to upload file:", str(e))

def SCA_scan_zip(project_id, upload_file_url, access_token=""):
    if(not access_token):
        access_token = SCA_get_access_token()
    
    url = f"{SCA_api_url}/api/scans/uploaded-zip"

    try:
        payload = {
            "projectId": project_id,
            "uploadedFileUrl": upload_file_url
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.post(url, headers=headers, json=payload, proxies=proxy_servers, verify=False)
        response.raise_for_status()  # Raise an error for bad responses

        response_json = response.json()
        # print('SCA_scan_zip scan_id:', response_json['scanId'])
        return response_json['scanId']
    except requests.RequestException as e:
        print("Exception: Failed to initiate scan:", str(e))
        return None
    
def SCA_get_scan_status(scan_id, access_token=""):
    if(not access_token):
        access_token = SCA_get_access_token()

    url = SCA_api_url + "/api/scans/" + scan_id

    try:
        payload = {}
        headers = {
        'Authorization': 'Bearer ' + access_token
        }

        response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
        status = response.content

        # Convert binary to string and parse JSON
        response_str = status.decode('utf-8')
        response_json = json.loads(response_str)

        # Get the status
        current_status = response_json.get('status')
   
    except Exception as e:
        print("Exception: SCA_get_scan_status", str(e))
        return ""
    else:
        print('SCA_get_scan_status')
        return current_status

def SCA_get_report(project_name, report_type, access_token=""):
    if(not access_token):
        access_token = SCA_get_access_token()

    scan_id = SCA_get_project_latest_scan_id(project_name, access_token)
    if scan_id:
        try:
            url = SCA_api_url + "/risk-management/risk-reports/" + scan_id + '/' + 'export?format=' + report_type + '&dataType[]=All'
        
            payload = {}
            headers = {
            'Authorization': 'Bearer ' + access_token
            }

            response = requests.request("GET", url, headers=headers, data=payload, proxies=proxy_servers, verify=False)
            pdf_content = response.content
            if report_type.lower() == 'csv':
                report_path = os.getcwd() + '\\' + project_name + '_SCA_report.zip'
            else:    
                report_path = os.getcwd() + '\\' + project_name + '_SCA_report.' + report_type
            with open(report_path, 'wb') as f:
                f.write(pdf_content)
        except Exception as e:
            print("Exception: SCA_get_report", str(e))
            return ""
        else:
            # print('SCA_get_report')
            return report_path
    else:
        return ""

def get_vulnerable_packages_from_report(project_name, access_token=""):
    try:
        if not access_token:
            access_token = SCA_get_access_token()

        SCA_report_path = SCA_get_report(project_name, 'csv', access_token)
        if not SCA_report_path:
            print(f"No SCA report found for project: {project_name}")
            return [], []

        # Step 4: Extract and process the CSV files from the zip
        csv_filename = 'Packages.csv'
        extracted_data = {}

        try:
            with zipfile.ZipFile(SCA_report_path, 'r') as zip_ref:
                with zip_ref.open(csv_filename) as csv_file:
                    extracted_data[csv_filename] = pd.read_csv(csv_file)

            # Process Packages.csv if it was successfully extracted
            if csv_filename in extracted_data:
                packages_df = extracted_data[csv_filename]

                # Ensure necessary columns exist before filtering
                required_columns = {'Severity', 'IsDirectDependency', 'Licenses'}
                if not required_columns.issubset(packages_df.columns):
                    print("Warning: Required columns not found in CSV")
                    return [], []

                # Convert columns to strings (avoid NaN type issues)
                packages_df['Severity'] = packages_df['Severity'].astype(str).str.lower()
                packages_df['Licenses'] = packages_df['Licenses'].astype(str)
                
                # Check if RiskScore column exists and handle it
                has_risk_score = 'RiskScore' in packages_df.columns
                if has_risk_score:
                    packages_df['RiskScore'] = packages_df['RiskScore'].fillna('N/A')  # Handle NaN values
                    print("RiskScore column found and will be included in results")
                else:
                    print("RiskScore column not found in CSV - will use 'N/A' as default")

                # Separate high-severity vulnerabilities and license issues
                vulnerabilities = []
                license_issues = []

                for _, row in packages_df.iterrows():
                    package_name = row['Name']
                    package_version = row['Version']
                    is_direct = row['IsDirectDependency']  # This is the boolean value we need
                    dependency_type = "(direct)" if is_direct else "(transitive)"
                    risk_score = row['RiskScore'] if has_risk_score else 'N/A'
                    
                    # Check if package is listed due to a restricted license
                    found_due_to_license = [
                        license for license in RESTRICTED_LICENSES if license in row['Licenses']
                    ]

                    # Classify package into the correct list - NOW INCLUDING is_direct boolean
                    if row['Severity'] == 'high':
                        vulnerabilities.append((package_name, package_version, dependency_type, risk_score, is_direct))
                    if found_due_to_license:
                        license_text = f" - Found due to {', '.join(found_due_to_license)} license"
                        license_issues.append((package_name, package_version, dependency_type + license_text, risk_score, is_direct))

                # Print vulnerabilities
                if vulnerabilities:
                    print(f"\nHigh Severity Vulnerable Packages in '{project_name}':")
                    for package, version, dep_type, risk_score, _ in vulnerabilities:  # Note: added _ for is_direct
                        print(f"- {package} {version} {dep_type} (RiskScore: {risk_score})")
                else:
                    print(f"No high severity packages found for project '{project_name}'.")

                # Print license issues
                if license_issues:
                    print(f"\nRestricted License Packages in '{project_name}':")
                    for package, version, dep_type, risk_score, _ in license_issues:  # Note: added _ for is_direct
                        print(f"- {package} {version} {dep_type} (RiskScore: {risk_score})")
                else:
                    print(f"No restricted license packages found for project '{project_name}'.")

                return vulnerabilities, license_issues

        except Exception as project_error:
            print(f"Error processing project '{project_name}': {project_error}")
            return [], []

        finally:
            # Delete the zip file after processing
            if os.path.exists(SCA_report_path):
                os.remove(SCA_report_path)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return [], []
    
def SCA_scan_packages(project_name, zip_manifest_file, team_name=None):
    access_token = SCA_get_access_token()
    global SCA_high_threshold
    global SHOW_RESULTS_DO_NOT_BREAK_BUILD
    global BREAK_ONLY_FOR_DIRECT
    global RISK_SCORE_THRESHOLD

    # Ensure SCA_high_threshold is an integer
    try:
        SCA_high_threshold = int(SCA_high_threshold)
        print(f"High vulnerability threshold set to: {SCA_high_threshold}")
    except (ValueError, TypeError):
        print(f"Warning: Invalid threshold value: '{SCA_high_threshold}'. Setting to default -1.")
        SCA_high_threshold = -1

    # Print risk score threshold setting
    if RISK_SCORE_THRESHOLD is not None:
        print(f"Risk score threshold set to: {RISK_SCORE_THRESHOLD}")
        print("Build will only break if at least one vulnerability has a risk score higher than this threshold")
    else:
        print("Risk score threshold: None (no risk score filtering)")
        
    if access_token:
        project_id = SCA_get_project_id(project_name, access_token)
        if (project_id == ''):
            project_id = SCA_create_project(project_name, access_token, team_name)
        if project_id:
            upload_file_url = SCA_get_upload_link(project_id, access_token)
            if upload_file_url:
                SCA_upload_file(upload_file_url, zip_manifest_file, access_token)
                scan_id = SCA_scan_zip(project_id, upload_file_url, access_token)

                print(f"Starting scan with high vulnerability threshold: {SCA_high_threshold}")
                if BREAK_ONLY_FOR_DIRECT:
                    print("Break only for direct vulnerabilities is ENABLED")
                
                if SCA_high_threshold is not None and SCA_high_threshold >= 0:
                    print(f"Will check vulnerabilities against threshold: {SCA_high_threshold}")
                    status = 'Running'
                    max_retries = 120  # 10 minutes with 5-second intervals
                    retries = 0

                    while status == 'Running' and retries < max_retries:
                        time.sleep(5)
                        retries += 1
                        status = SCA_get_scan_status(scan_id, access_token)
                        print(f'Scan status: {status} (attempt {retries}/{max_retries})')

                    if retries >= max_retries and status == 'Running':
                        print("Scan timed out after 10 minutes")
                        return None

                    try: 
                        vulnerabilities, license_issues = get_vulnerable_packages_from_report(project_name, access_token)
                        
                        issues_found = False
                        build_should_break = False
                        
                        # Check vulnerabilities against threshold
                        if BREAK_ONLY_FOR_DIRECT:
                            # Count only direct vulnerabilities
                            direct_vulnerabilities = [v for v in vulnerabilities if v[4] == True]  # v[4] is is_direct
                            direct_vulnerability_count = len(direct_vulnerabilities)
                            total_vulnerability_count = len(vulnerabilities)
                            
                            print(f"Direct vulnerabilities found: {direct_vulnerability_count}")
                            print(f"Total vulnerabilities found: {total_vulnerability_count}")
                            
                            # Check if vulnerability count exceeds threshold (primary rule)
                            if direct_vulnerability_count > SCA_high_threshold:
                                print(f"Direct vulnerability threshold exceeded: {direct_vulnerability_count} > {SCA_high_threshold}")
                                issues_found = True
                                build_should_break = True
                            else:
                                # Count doesn't exceed threshold, but check risk score filtering (additional rule)
                                if RISK_SCORE_THRESHOLD is not None and direct_vulnerabilities:
                                    high_risk_direct_vulns = []
                                    for vuln in direct_vulnerabilities:
                                        risk_score = parse_risk_score(vuln[3])  # vuln[3] is risk_score
                                        if risk_score is not None and risk_score > RISK_SCORE_THRESHOLD:
                                            high_risk_direct_vulns.append(vuln)
                                    
                                    print(f"Direct vulnerabilities with risk score > {RISK_SCORE_THRESHOLD}: {len(high_risk_direct_vulns)}")
                                    if len(high_risk_direct_vulns) > 0:
                                        for vuln in high_risk_direct_vulns:
                                            print(f"  - {vuln[0]} {vuln[1]} (RiskScore: {vuln[3]})")
                                        print(f"Breaking build due to high-risk vulnerabilities (even though count less or equal threshold)")
                                        issues_found = True
                                        build_should_break = True
                                    else:
                                        print(f"Direct vulnerability count ({direct_vulnerability_count}) does not exceed threshold ({SCA_high_threshold}) and no high-risk vulnerabilities found")
                                        if direct_vulnerability_count > 0:
                                            issues_found = True
                                            # build_should_break remains False
                                else:
                                    # No risk score filtering
                                    print(f"Direct vulnerability count ({direct_vulnerability_count}) does not exceed threshold ({SCA_high_threshold})")
                                    if direct_vulnerability_count > 0:
                                        issues_found = True
                                        # build_should_break remains False
                            
                            if total_vulnerability_count > direct_vulnerability_count:
                                transitive_count = total_vulnerability_count - direct_vulnerability_count
                                print(f"Found {transitive_count} transitive vulnerabilities, but not breaking build (BreakOnlyForDirect=True)")
                                issues_found = True
                                # build_should_break remains False for transitive vulns
                        else:
                            # Original behavior - count all vulnerabilities
                            high_vulnerability_count = len(vulnerabilities)
                            
                            # Check if vulnerability count exceeds threshold (primary rule)
                            if high_vulnerability_count > SCA_high_threshold:
                                print(f"High vulnerability threshold exceeded: {high_vulnerability_count} > {SCA_high_threshold}")
                                issues_found = True
                                build_should_break = True
                            else:
                                # Count doesn't exceed threshold, but check risk score filtering (additional rule)
                                if RISK_SCORE_THRESHOLD is not None and vulnerabilities:
                                    high_risk_vulns = []
                                    for vuln in vulnerabilities:
                                        risk_score = parse_risk_score(vuln[3])  # vuln[3] is risk_score
                                        if risk_score is not None and risk_score > RISK_SCORE_THRESHOLD:
                                            high_risk_vulns.append(vuln)
                                    
                                    print(f"Vulnerabilities with risk score > {RISK_SCORE_THRESHOLD}: {len(high_risk_vulns)}")
                                    if len(high_risk_vulns) > 0:
                                        for vuln in high_risk_vulns:
                                            print(f"  - {vuln[0]} {vuln[1]} {vuln[2]} (RiskScore: {vuln[3]})")
                                        print(f"Breaking build due to high-risk vulnerabilities (even though count less or equal threshold)")
                                        issues_found = True
                                        build_should_break = True
                                    else:
                                        print(f"Vulnerability count ({high_vulnerability_count}) does not exceed threshold ({SCA_high_threshold}) and no high-risk vulnerabilities found")
                                        if high_vulnerability_count > 0:
                                            issues_found = True
                                            # build_should_break remains False
                                else:
                                    # No risk score filtering
                                    print(f"Vulnerability count ({high_vulnerability_count}) does not exceed threshold ({SCA_high_threshold})")
                                    if high_vulnerability_count > 0:
                                        issues_found = True
                                        # build_should_break remains False
    
                        # Check license issues (always break if found, regardless of BREAK_ONLY_FOR_DIRECT)
                        if len(license_issues) > 0:
                            print(f"License issues found: {len(license_issues)}")
                            issues_found = True
                            if BREAK_ONLY_FOR_DIRECT:
                                # For license issues with BREAK_ONLY_FOR_DIRECT, only break on direct dependencies
                                direct_license_issues = [l for l in license_issues if l[4] == True]  # l[4] is is_direct
                                if len(direct_license_issues) > 0:
                                    print(f"Direct license issues found: {len(direct_license_issues)} - will break build")
                                    build_should_break = True
                                else:
                                    print(f"Only transitive license issues found - not breaking build (BreakOnlyForDirect=True)")
                            else:
                                build_should_break = True
                            
                        if build_should_break and not SHOW_RESULTS_DO_NOT_BREAK_BUILD:
                            print("Breaking build due to issues found")
                            return 1
                        elif issues_found:
                            if SHOW_RESULTS_DO_NOT_BREAK_BUILD:
                                print("Issues found but not breaking build (SHOW_RESULTS_DO_NOT_BREAK_BUILD=True)")
                            elif BREAK_ONLY_FOR_DIRECT and not build_should_break:
                                print("Issues found but not breaking build (only transitive issues and BreakOnlyForDirect=True)")
                            elif RISK_SCORE_THRESHOLD is not None and not build_should_break:
                                print(f"Issues found but not breaking build (no vulnerabilities with risk score > {RISK_SCORE_THRESHOLD})")
                            return 0
                                
                        return 0
                    except Exception as e:
                        print(f"Error analyzing report: {str(e)}")
                        return None
                else:
                    print("Skipping vulnerability threshold check")
                    return 0
            else:
                print("Failed to get upload URL")
        else:
            print("Failed to get or create project ID")
    else:
        print("Failed to get access token")
    
    return None

# New function to process package.json files and remove excluded packages
def process_package_json(file_path, temp_dir):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        modified = False
        
        # Process dependencies
        if 'dependencies' in data:
            orig_deps = data['dependencies'].copy()
            for exclude in EXCLUDE_PACKAGES:
                pkg_name = exclude['package']
                version = exclude['version']
                
                if pkg_name in data['dependencies']:
                    # If version is empty or matches the dependency version
                    if not version or data['dependencies'][pkg_name] == version or data['dependencies'][pkg_name].strip('^~>=<') == version.strip('^~>=<'):
                        del data['dependencies'][pkg_name]
                        print(f"Excluded {pkg_name}@{version if version else 'all versions'} from dependencies")
                        modified = True
        
        # Process devDependencies - remove them if REMOVE_DEV_DEPENDENCIES is True
        if 'devDependencies' in data:
            # If we should remove all dev dependencies
            if REMOVE_DEV_DEPENDENCIES:
                print(f"Removing all devDependencies as per configuration")
                del data['devDependencies']
                modified = True
            else:
                # Otherwise just remove excluded packages from devDependencies
                orig_dev_deps = data['devDependencies'].copy()
                for exclude in EXCLUDE_PACKAGES:
                    pkg_name = exclude['package']
                    version = exclude['version']
                    
                    if pkg_name in data['devDependencies']:
                        # If version is empty or matches the dependency version
                        if not version or data['devDependencies'][pkg_name] == version or data['devDependencies'][pkg_name].strip('^~>=<') == version.strip('^~>=<'):
                            del data['devDependencies'][pkg_name]
                            print(f"Excluded {pkg_name}@{version if version else 'all versions'} from devDependencies")
                            modified = True
        
        if modified:
            # Create a filename based on the original filename without the full path
            filename = os.path.basename(file_path)
            new_file_path = os.path.join(temp_dir, filename)
            
            with open(new_file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            return new_file_path
        
        return file_path
    except Exception as e:
        print(f"Error processing package.json {file_path}: {e}")
        return file_path

# New function to process packages.config files
def process_packages_config(file_path, temp_dir):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        modified = False
        
        # Find and remove excluded packages
        for exclude in EXCLUDE_PACKAGES:
            pkg_name = exclude['package']
            version = exclude['version']
            
            for package in root.findall(".//package"):
                if package.get('id') == pkg_name:
                    # If version is empty or matches
                    if not version or package.get('version') == version:
                        root.remove(package)
                        print(f"Excluded {pkg_name}@{version if version else 'all versions'} from packages.config")
                        modified = True
                        
                # Check for developmentDependency attribute if REMOVE_DEV_DEPENDENCIES is True
                if REMOVE_DEV_DEPENDENCIES and package.get('developmentDependency') == 'true':
                    root.remove(package)
                    print(f"Removed development dependency: {package.get('id')}")
                    modified = True
        
        if modified:
            # Create a filename based on the original filename without the full path
            filename = os.path.basename(file_path)
            new_file_path = os.path.join(temp_dir, filename)
            
            tree.write(new_file_path)
            return new_file_path
        
        return file_path
    except Exception as e:
        print(f"Error processing packages.config {file_path}: {e}")
        return file_path

# New function to process csproj files
def process_csproj(file_path, temp_dir):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        modified = False
        
        # Find and remove excluded packages
        for exclude in EXCLUDE_PACKAGES:
            pkg_name = exclude['package']
            version = exclude['version']
            
            print('pkg_name '+ pkg_name)
            
            # Find all ItemGroup elements first
            for item_group in root.findall(".//ItemGroup"):
                # Then check each PackageReference within each ItemGroup
                for package_ref in item_group.findall("PackageReference"):
                    if package_ref.get('Include') == pkg_name:
                        # If version is empty or matches
                        if not version or package_ref.get('Version') == version:
                            item_group.remove(package_ref)
                            print(f"Excluded {pkg_name}@{version if version else 'all versions'} from csproj")
                            modified = True
                    
                    # Check for DevelopmentDependency attribute if REMOVE_DEV_DEPENDENCIES is True
                    if REMOVE_DEV_DEPENDENCIES and package_ref.get('DevelopmentDependency') == 'true':
                        item_group.remove(package_ref)
                        print(f"Removed development dependency: {package_ref.get('Include')}")
                        modified = True
        
        if modified:
            # Create a filename based on the original filename without the full path
            filename = os.path.basename(file_path)
            new_file_path = os.path.join(temp_dir, filename)
            
            tree.write(new_file_path)
            return new_file_path
        
        return file_path
    except Exception as e:
        print(f"Error processing csproj {file_path}: {e}")
        return file_path
        
# New function to process Directory.Packages.props files
def process_directory_packages(file_path, temp_dir):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        modified = False
        
        # Find all parent elements that might contain PackageVersion elements
        for item_group in root.findall(".//ItemGroup"):
            # Find and remove excluded packages
            for package_version in item_group.findall("PackageVersion"):
                # Check if this package is in our exclude list
                for exclude in EXCLUDE_PACKAGES:
                    pkg_name = exclude['package']
                    version = exclude['version']
                    
                    if package_version.get('Include') == pkg_name:
                        # If version is empty or matches
                        if not version or package_version.get('Version') == version:
                            item_group.remove(package_version)
                            print(f"Excluded {pkg_name}@{version if version else 'all versions'} from Directory.Packages.props")
                            modified = True
                
                # Check for DevelopmentDependency attribute if REMOVE_DEV_DEPENDENCIES is True
                if REMOVE_DEV_DEPENDENCIES and package_version.get('DevelopmentDependency') == 'true':
                    item_group.remove(package_version)
                    print(f"Removed development dependency: {package_version.get('Include')}")
                    modified = True
        
        if modified:
            # Create a filename based on the original filename without the full path
            filename = os.path.basename(file_path)
            new_file_path = os.path.join(temp_dir, filename)
            
            tree.write(new_file_path)
            return new_file_path
        
        return file_path
    except Exception as e:
        print(f"Error processing Directory.Packages.props {file_path}: {e}")
        return file_path
    
# New function to process requirements.txt files
def process_requirements_txt(file_path, temp_dir):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        modified = False
        new_lines = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                new_lines.append(line)
                continue
                
            # Parse package name and version
            if '==' in line:
                parts = line.split('==')
                pkg_name = parts[0].strip()
                pkg_version = parts[1].strip()
            elif '>=' in line:
                parts = line.split('>=')
                pkg_name = parts[0].strip()
                pkg_version = parts[1].strip()
            elif '<=' in line:
                parts = line.split('<=')
                pkg_name = parts[0].strip()
                pkg_version = parts[1].strip()
            else:
                # No version specified
                pkg_name = line.strip()
                pkg_version = ""
            
            # Check if package should be excluded
            exclude_this = False
            for exclude in EXCLUDE_PACKAGES:
                if exclude['package'] == pkg_name:
                    if not exclude['version'] or exclude['version'] == pkg_version:
                        print(f"Excluded {pkg_name}@{pkg_version if pkg_version else 'all versions'} from requirements.txt")
                        exclude_this = True
                        modified = True
                        break
            
            # Check for dev packages (typically indicated by a comment)
            if REMOVE_DEV_DEPENDENCIES and ('#' in line and any(dev_marker in line.lower() for dev_marker in ['dev ', 'development', 'test'])):
                print(f"Excluded development dependency: {pkg_name}")
                exclude_this = True
                modified = True
            
            if not exclude_this:
                new_lines.append(line)
        
        if modified:
            # Create a filename based on the original filename without the full path
            filename = os.path.basename(file_path)
            new_file_path = os.path.join(temp_dir, filename)
            
            with open(new_file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(new_lines))
            
            return new_file_path
        
        return file_path
    except Exception as e:
        print(f"Error processing requirements.txt {file_path}: {e}")
        return file_path

# New function to process pom.xml files
def process_pom_xml(file_path, temp_dir):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        # Handle default namespace in pom.xml
        namespaces = {'m': 'http://maven.apache.org/POM/4.0.0'}
        modified = False
        
        # Find and remove excluded dependencies
        for exclude in EXCLUDE_PACKAGES:
            pkg_name = exclude['package']
            version = exclude['version']
            
            # Find dependencies with matching artifactId
            for dependency in root.findall(".//m:dependencies/m:dependency", namespaces):
                artifact_id = dependency.find("m:artifactId", namespaces)
                
                if artifact_id is not None and artifact_id.text == pkg_name:
                    # If version is empty or matches
                    dep_version = dependency.find("m:version", namespaces)
                    if not version or (dep_version is not None and dep_version.text == version):
                        # Remove from parent
                        parent = dependency.getparent()
                        if parent is not None:
                            parent.remove(dependency)
                            print(f"Excluded {pkg_name}@{version if version else 'all versions'} from pom.xml")
                            modified = True
                
                # Check for scope element (test, provided) if REMOVE_DEV_DEPENDENCIES is True
                if REMOVE_DEV_DEPENDENCIES:
                    scope = dependency.find("m:scope", namespaces)
                    if scope is not None and scope.text in ['test', 'provided']:
                        parent = dependency.getparent()
                        if parent is not None:
                            parent.remove(dependency)
                            artifact_id_text = artifact_id.text if artifact_id is not None else "unknown"
                            print(f"Removed {scope.text} dependency: {artifact_id_text}")
                            modified = True
        
        if modified:
            # Create a filename based on the original filename without the full path
            filename = os.path.basename(file_path)
            new_file_path = os.path.join(temp_dir, filename)
            
            tree.write(new_file_path)
            return new_file_path
        
        return file_path
    except Exception as e:
        print(f"Error processing pom.xml {file_path}: {e}")
        return file_path

# New function to process composer.json files
def process_composer_json(file_path, temp_dir):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        modified = False
        
        # Process require section
        if 'require' in data:
            orig_deps = data['require'].copy()
            for exclude in EXCLUDE_PACKAGES:
                pkg_name = exclude['package']
                version = exclude['version']
                
                if pkg_name in data['require']:
                    # If version is empty or matches the dependency version
                    if not version or data['require'][pkg_name] == version or data['require'][pkg_name].strip('^~>=<') == version.strip('^~>=<'):
                        del data['require'][pkg_name]
                        print(f"Excluded {pkg_name}@{version if version else 'all versions'} from composer.json require")
                        modified = True
        
        # Process require-dev section
        if 'require-dev' in data:
            # If we should remove all dev dependencies
            if REMOVE_DEV_DEPENDENCIES:
                print(f"Removing all require-dev dependencies as per configuration")
                del data['require-dev']
                modified = True
            else:
                # Otherwise just remove excluded packages from require-dev
                orig_dev_deps = data['require-dev'].copy()
                for exclude in EXCLUDE_PACKAGES:
                    pkg_name = exclude['package']
                    version = exclude['version']
                    
                    if pkg_name in data['require-dev']:
                        # If version is empty or matches the dependency version
                        if not version or data['require-dev'][pkg_name] == version or data['require-dev'][pkg_name].strip('^~>=<') == version.strip('^~>=<'):
                            del data['require-dev'][pkg_name]
                            print(f"Excluded {pkg_name}@{version if version else 'all versions'} from composer.json require-dev")
                            modified = True
        
        if modified:
            # Create a filename based on the original filename without the full path
            filename = os.path.basename(file_path)
            new_file_path = os.path.join(temp_dir, filename)
            
            with open(new_file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            return new_file_path
        
        return file_path
    except Exception as e:
        print(f"Error processing composer.json {file_path}: {e}")
        return file_path

def zip_folder(folder_to_zip, output_folder='src', remove_dev_dependencies=True, exclude_folders=None):
    try:
        # Set the global REMOVE_DEV_DEPENDENCIES flag
        global REMOVE_DEV_DEPENDENCIES
        REMOVE_DEV_DEPENDENCIES = remove_dev_dependencies
        print(f"Remove development dependencies setting: {REMOVE_DEV_DEPENDENCIES}")
        
        # Process exclude_folders parameter
        if exclude_folders is None:
            exclude_folders = []
        elif isinstance(exclude_folders, str):
            exclude_folders = [exclude_folders]
        
        # Convert to set for faster lookup and normalize folder names
        exclude_folders_set = {folder.strip().lower() for folder in exclude_folders}
        if exclude_folders_set:
            print(f"Excluding folders: {', '.join(exclude_folders_set)}")
        
        # Get the current working directory
        current_directory = os.getcwd()

        # Create the output folder if it doesn't exist
        output_folder_path = os.path.join(current_directory, output_folder)
        if not os.path.exists(output_folder_path):
            os.makedirs(output_folder_path)

        # Extract the folder name to use as the zip file name
        folder_name = os.path.basename(os.path.normpath(folder_to_zip))
        zip_file_name = folder_name + '.zip'
        zip_file_path = os.path.join(output_folder_path, zip_file_name)

        # Create a temporary directory for modified files
        temp_dir = tempfile.mkdtemp(prefix="sca_modified_")
        
        try:
            # First pass: Find all Directory.Packages.props files to track which folders have them
            props_files_found = []
            for root, dirs, files in os.walk(folder_to_zip):
                # Filter out excluded directories from the walk
                dirs[:] = [d for d in dirs if d.lower() not in exclude_folders_set]
                
                if 'Directory.Packages.props' in files:
                    props_files_found.append(os.path.join(root, 'Directory.Packages.props'))
                    print(f"DEBUG: Found Directory.Packages.props at: {root}")
            
            # If any Directory.Packages.props files are found, exclude ALL .csproj files from the entire scan
            # This is because centralized package management affects the entire solution
            exclude_all_csproj = len(props_files_found) > 0
            
            if exclude_all_csproj:
                print(f"DEBUG: Found {len(props_files_found)} Directory.Packages.props files - will exclude ALL .csproj files from zip")
                for props_file in props_files_found:
                    print(f"  - {props_file}")
            else:
                print("DEBUG: No Directory.Packages.props files found - will include .csproj files normally")
            
            # Debug: Track files added to zip
            files_added_to_zip = []
            folders_excluded_count = 0
            
            # Create the zip file
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(folder_to_zip):
                    # Filter out excluded directories from the walk
                    original_dirs_count = len(dirs)
                    dirs[:] = [d for d in dirs if d.lower() not in exclude_folders_set]
                    excluded_in_this_level = original_dirs_count - len(dirs)
                    folders_excluded_count += excluded_in_this_level
                    
                    # Skip processing files if the current directory itself is excluded
                    current_folder_name = os.path.basename(root).lower()
                    if current_folder_name in exclude_folders_set:
                        print(f"DEBUG: Skipping excluded folder: {root}")
                        continue
                    
                    for file in files:
                        try:
                            # Check if the file matches any of the patterns
                            if any(fnmatch.fnmatch(file, pattern) for pattern in manifest_patterns):
                                file_path = os.path.join(root, file)
                                rel_path = os.path.relpath(file_path, folder_to_zip)
                                
                                # Skip ALL .csproj files if ANY Directory.Packages.props exists in the solution
                                if file.endswith('.csproj') and exclude_all_csproj:
                                    print(f"DEBUG: Skipping {file} in {root} because centralized package management (Directory.Packages.props) is used in this solution")
                                    continue  # Skip adding this file to the zip
                                
                                # Process different manifest file types to exclude packages
                                processed_file_path = file_path
                                
                                if file == 'package.json':
                                    processed_file_path = process_package_json(file_path, temp_dir)
                                    files_added_to_zip.append(f"package.json: {rel_path}")
                                elif file == 'packages.config':
                                    processed_file_path = process_packages_config(file_path, temp_dir)
                                    files_added_to_zip.append(f"packages.config: {rel_path}")
                                elif file.endswith('.csproj'):
                                    processed_file_path = process_csproj(file_path, temp_dir)
                                    files_added_to_zip.append(f"csproj: {rel_path}")
                                elif file == 'Directory.Packages.props':
                                    print(f"DEBUG: Processing Directory.Packages.props: {file_path}")
                                    processed_file_path = process_directory_packages(file_path, temp_dir)
                                    # Convert to csproj and add only the converted file
                                    converted_csproj = os.path.join(temp_dir, f'converted_{os.path.basename(root)}.csproj')
                                    convert_directory_packages_to_csproj(processed_file_path, converted_csproj)
                                    
                                    # Debug: Show contents of converted file
                                    try:
                                        with open(converted_csproj, 'r') as debug_file:
                                            content = debug_file.read()
                                            print(f"DEBUG: Converted csproj content preview (first 500 chars):")
                                            print(content[:500])
                                            print("DEBUG: ...")
                                    except Exception as e:
                                        print(f"DEBUG: Could not read converted file: {e}")
                                    
                                    converted_rel_path = os.path.join(os.path.dirname(rel_path), f'converted_{os.path.basename(root)}.csproj')
                                    zipf.write(converted_csproj, converted_rel_path)
                                    files_added_to_zip.append(f"converted csproj: {converted_rel_path}")
                                    print(f"DEBUG: Added converted {file} as {os.path.basename(converted_csproj)} and skipped original file")
                                    continue  # Skip adding the original Directory.Packages.props file
                                elif file == 'requirements.txt':
                                    processed_file_path = process_requirements_txt(file_path, temp_dir)
                                    files_added_to_zip.append(f"requirements.txt: {rel_path}")
                                elif file == 'pom.xml':
                                    processed_file_path = process_pom_xml(file_path, temp_dir)
                                    files_added_to_zip.append(f"pom.xml: {rel_path}")
                                elif file == 'composer.json':
                                    processed_file_path = process_composer_json(file_path, temp_dir)
                                    files_added_to_zip.append(f"composer.json: {rel_path}")
                                
                                # Add the processed file to the zip (except for Directory.Packages.props which was handled above)
                                if file != 'Directory.Packages.props':
                                    zipf.write(processed_file_path, rel_path)
                            
                        except Exception as e:
                            print(f"Error processing file {file}: {e}")
                            import traceback
                            traceback.print_exc()
                
            # Debug: Show all files added to zip and exclusion summary
            print(f"DEBUG: Total files added to zip: {len(files_added_to_zip)}")
            if folders_excluded_count > 0:
                print(f"DEBUG: Total folders excluded: {folders_excluded_count}")
            for added_file in files_added_to_zip:
                print(f"  - {added_file}")
                
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir, ignore_errors=True)
                            
        # print(f"Successfully created zip file: {zip_file_path}")
        return zip_file_path

    except Exception as e:
        print(f"Error zipping folder {folder_to_zip}: {e}")
        import traceback
        traceback.print_exc()
        return None
    
def convert_directory_packages_to_csproj(props_file_path, csproj_output_path):
    try:
        print(f"DEBUG: Starting conversion of {props_file_path}")
        
        # Parse the Directory.Packages.props file
        tree = ET.parse(props_file_path)
        root = tree.getroot()

        # Debug: Show what we found in the props file
        package_versions = root.findall(".//PackageVersion")
        print(f"DEBUG: Found {len(package_versions)} PackageVersion elements in props file")
        
        # Create a list to store PackageReference elements
        package_references = []
        packages_processed = 0

        # Find all PackageVersion elements and create corresponding PackageReference elements
        for package_version in package_versions:
            package_id = package_version.get('Include')
            package_version_value = package_version.get('Version')
            
            if package_id and package_version_value:
                packages_processed += 1
                if packages_processed <= 5:  # Show first 5 packages for debugging
                    print(f"DEBUG: Converting package {package_id} version {package_version_value}")
                
                package_ref = f'    <PackageReference Include="{package_id}" Version="{package_version_value}" />'
                package_references.append(package_ref)
            else:
                print(f"DEBUG: WARNING - Package missing Include or Version: Include={package_id}, Version={package_version_value}")

        print(f"DEBUG: Successfully processed {packages_processed} packages for conversion")

        # Generate the .csproj content
        csproj_content = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
"""
        # Append all PackageReference elements
        csproj_content += "\n".join(package_references)
        
        # Close the ItemGroup and Project tags
        csproj_content += """
  </ItemGroup>
</Project>"""

        # Write the content to the output .csproj file
        with open(csproj_output_path, 'w') as csproj_file:
            csproj_file.write(csproj_content)

        print(f"DEBUG: Successfully converted {props_file_path} to {csproj_output_path}")
        print(f"DEBUG: Converted file size: {os.path.getsize(csproj_output_path)} bytes")

    except ET.ParseError as e:
        print(f"DEBUG: XML parsing error in {props_file_path}: {e}")
    except Exception as e:
        print(f"DEBUG: Error converting {props_file_path} to {csproj_output_path}: {e}")
        import traceback
        traceback.print_exc()

def validate_csproj_dependencies(csproj_path):
    """Verify that all PackageReference elements in the .csproj have a Version attribute."""
    try:
        tree = ET.parse(csproj_path)
        root = tree.getroot()

        # Check for PackageReference elements without a Version attribute
        for package_ref in root.findall(".//PackageReference"):
            if package_ref.get('Version') is None:
                return False
        return True

    except ET.ParseError as e:
        print(f"XML parsing error in {csproj_path}: {e}")
        return False
    except Exception as e:
        print(f"Error validating dependencies in {csproj_path}: {e}")
        return False
        
#################################################
# main code
#################################################
def main():
    # Initialize variables at the start to avoid UnboundLocalError
    zip_file_name = None  
    scan_status = 0

    try:
        parser = argparse.ArgumentParser(
            description="ScareSolver - Tool for scanning packages in a source folder"
        )
        parser.add_argument("file_path", help="The path to the source folder to scan.")
        parser.add_argument("project_name", help="The name of the project.")
        parser.add_argument("--team_name", default="", help="Optional: The name of the team.")
        parser.add_argument("--show_results", dest="show_results", action='store_true', help="Set to show results without breaking build (default: False)")
        parser.add_argument("--exclude_folders", nargs='*', default=[], help="Optional: List of folder names to exclude from scanning (e.g., --exclude_folders node_modules bin obj)")

        args = parser.parse_args()

        source_folder = args.file_path
        project_name = args.project_name
        team_name = args.team_name
        exclude_folders = args.exclude_folders
        
        # Important: Only override the global setting if the command line argument is provided
        global SHOW_RESULTS_DO_NOT_BREAK_BUILD
        if args.show_results:
            SHOW_RESULTS_DO_NOT_BREAK_BUILD = True
            print(f"Command line override: SHOW_RESULTS_DO_NOT_BREAK_BUILD set to {SHOW_RESULTS_DO_NOT_BREAK_BUILD}")
        else:
            print(f"Using default setting: SHOW_RESULTS_DO_NOT_BREAK_BUILD = {SHOW_RESULTS_DO_NOT_BREAK_BUILD}")

        if package_exclude_json:
            # Read package exclusion list from JSON file provided
            try:
                load_exclude_packages(package_exclude_json)
            except Exception as e:
                print(f"Error loading exclude packages JSON: {e}")
                sys.exit(1)

        print(f"Source folder = {source_folder}")
        print(f"Project name = {project_name}")
        if team_name:
            print(f"Team name = {team_name}")
        if exclude_folders:
            print(f"Excluded folders = {', '.join(exclude_folders)}")

        zip_file_name = zip_folder(source_folder, 'src', exclude_folders=exclude_folders)

        if zip_file_name and os.path.exists(zip_file_name):
            # If zip file is generated, proceed with scanning
            scan_status = SCA_scan_packages(project_name, zip_file_name, team_name)
        else:
            print("Error: Failed to create zip file or zip file not found")
            sys.exit(1)

    except SystemExit as e:
        print(f"SystemExit: {e}. Check if required arguments are provided.")
        raise
    except Exception as e:
        print("Exception in main:", str(e))
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Delete the zip file after processing
        if zip_file_name and os.path.exists(zip_file_name):
            os.remove(zip_file_name)

        if scan_status == 1:
            print("Error -1: High vulnerability threshold exceeded")
            sys.exit(-1)
        else:
            print("Exit 0: Scan completed successfully")
            sys.exit(0)
            
if __name__ == '__main__':
   main()