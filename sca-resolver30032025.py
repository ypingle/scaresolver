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

SCA_account = 'moj'
SCA_username = 'yoel2b'
SCA_password = 'Bb12345678!'
SCA_url = 'https://eu.sca.checkmarx.net'
SCA_api_url = 'https://eu.api-sca.checkmarx.net'
SCA_auth_url = 'https://eu.platform.checkmarx.net/identity/connect/token'
SCA_high_threshold = 0
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

                # Separate high-severity vulnerabilities and license issues
                vulnerabilities = []
                license_issues = []

                for _, row in packages_df.iterrows():
                    package_name = row['Name']
                    package_version = row['Version']
                    dependency_type = "(direct)" if row['IsDirectDependency'] else "(transitive)"
                    
                    # Check if package is listed due to a restricted license
                    found_due_to_license = [
                        license for license in RESTRICTED_LICENSES if license in row['Licenses']
                    ]

                    # Classify package into the correct list
                    if row['Severity'] == 'high':
                        vulnerabilities.append((package_name, package_version, dependency_type))
                    if found_due_to_license:
                        license_text = f" - Found due to {', '.join(found_due_to_license)} license"
                        license_issues.append((package_name, package_version, dependency_type + license_text))

                # Print vulnerabilities
                if vulnerabilities:
                    print(f"\nHigh Severity Vulnerable Packages in '{project_name}':")
                    for package, version, dep_type in vulnerabilities:
                        print(f"- {package} {version} {dep_type}")
                else:
                    print(f"No high severity packages found for project '{project_name}'.")

                # Print license issues
                if license_issues:
                    print(f"\nRestricted License Packages in '{project_name}':")
                    for package, version, dep_type in license_issues:
                        print(f"- {package} {version} {dep_type}")
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

    # Ensure SCA_high_threshold is an integer
    try:
        SCA_high_threshold = int(SCA_high_threshold)
        print(f"High vulnerability threshold set to: {SCA_high_threshold}")
    except (ValueError, TypeError):
        print(f"Warning: Invalid threshold value: '{SCA_high_threshold}'. Setting to default -1.")
        SCA_high_threshold = -1
        
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
                        high_vulnerability_count = len(vulnerabilities)
                        
                        issues_found = False
                        
                        if high_vulnerability_count > SCA_high_threshold:
                            print(f"High vulnerability threshold exceeded: {high_vulnerability_count} > {SCA_high_threshold}")
                            issues_found = True
    
                        if len(license_issues) > 0:
                            print(f"License issues found: {len(license_issues)}")
                            issues_found = True
                            
                        if issues_found and not SHOW_RESULTS_DO_NOT_BREAK_BUILD:
                            print("Breaking build due to issues found")
                            return 1
                        elif issues_found:
                            print("Issues found but not breaking build (SHOW_RESULTS_DO_NOT_BREAK_BUILD=True)")
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

def zip_folder(folder_to_zip, output_folder='src', remove_dev_dependencies=True):
    try:
        # Set the global REMOVE_DEV_DEPENDENCIES flag
        global REMOVE_DEV_DEPENDENCIES
        REMOVE_DEV_DEPENDENCIES = remove_dev_dependencies
        print(f"Remove development dependencies setting: {REMOVE_DEV_DEPENDENCIES}")
        
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
            # Create the zip file
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(folder_to_zip):
                    for file in files:
                        try:
                            # Check if the file matches any of the patterns
                            if any(fnmatch.fnmatch(file, pattern) for pattern in manifest_patterns):
                                file_path = os.path.join(root, file)
                                rel_path = os.path.relpath(file_path, folder_to_zip)
                                
                                # Process different manifest file types to exclude packages
                                processed_file_path = file_path
                                
                                if file == 'package.json':
                                    processed_file_path = process_package_json(file_path, temp_dir)
                                elif file == 'packages.config':
                                    processed_file_path = process_packages_config(file_path, temp_dir)
                                elif file.endswith('.csproj'):
                                    processed_file_path = process_csproj(file_path, temp_dir)
                                elif file == 'Directory.Packages.props':
                                    processed_file_path = process_directory_packages(file_path, temp_dir)
                                    # Also convert to csproj
                                    converted_csproj = os.path.join(temp_dir, 'converted.csproj')
                                    convert_directory_packages_to_csproj(processed_file_path, converted_csproj)
                                    zipf.write(converted_csproj, 'converted.csproj')
                                elif file == 'requirements.txt':
                                    processed_file_path = process_requirements_txt(file_path, temp_dir)
                                elif file == 'pom.xml':
                                    processed_file_path = process_pom_xml(file_path, temp_dir)
                                elif file == 'composer.json':
                                    processed_file_path = process_composer_json(file_path, temp_dir)
                                
                                # Add the processed file to the zip
                                zipf.write(processed_file_path, rel_path)
                            
                        except Exception as e:
                            print(f"Error processing file {file}: {e}")
                
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir, ignore_errors=True)
                            
        # print(f"Successfully created zip file: {zip_file_path}")
        return zip_file_path

    except Exception as e:
        print(f"Error zipping folder {folder_to_zip}: {e}")
        return None

def convert_directory_packages_to_csproj(props_file_path, csproj_output_path):
    try:
        # Parse the Directory.Packages.props file
        tree = ET.parse(props_file_path)
        root = tree.getroot()

        # Create a list to store PackageReference elements
        package_references = []

        # Find all PackageVersion elements and create corresponding PackageReference elements
        for package_version in root.findall(".//PackageVersion"):
            package_id = package_version.get('Include')
            package_version_value = package_version.get('Version')

            # Create the PackageReference element for .csproj with the correct version
            package_ref = f"""
    <ItemGroup>
        <PackageReference Include="{package_id}" Version="{package_version_value}" />
    </ItemGroup>
            """
            package_references.append(package_ref)

        # Generate the .csproj content
        csproj_content = """
<Project Sdk="Microsoft.NET.Sdk">
    <PropertyGroup>
        <TargetFramework>netstandard2.0</TargetFramework>
    </PropertyGroup>
"""
        # Append all PackageReference elements
        csproj_content += "\n".join(package_references)
        
        # Close the Project tag
        csproj_content += "\n</Project>"

        # Write the content to the output .csproj file
        with open(csproj_output_path, 'w') as csproj_file:
            csproj_file.write(csproj_content)

        print(f"Successfully converted {props_file_path} to {csproj_output_path}")

    except ET.ParseError as e:
        print(f"XML parsing error in {props_file_path}: {e}")
    except Exception as e:
        print(f"Error converting {props_file_path} to {csproj_output_path}: {e}")

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

        args = parser.parse_args()

        source_folder = args.file_path
        project_name = args.project_name
        team_name = args.team_name

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

        zip_file_name = zip_folder(source_folder, 'src')

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