import requests
import os
import sys
import time
import zipfile
import argparse
import traceback
import pandas as pd
import urllib3
from datetime import datetime, timedelta
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#########################################
# SCA Portal Configuration:
#########################################

#SCA_account = 'moj'
#SCA_username = 'yoel2b'
#SCA_password = 'Bb12345678!'

SCA_account = 'rmi'
SCA_username = 'yoel.pingle'
SCA_password = 'AaBb6636202#'

#SCA_account = 'sca_2bsecure'
#SCA_username = 'yoelp'
#SCA_password = 'pLA0msan23A!'

SCA_proxy = ''

SCA_url = 'https://eu.sca.checkmarx.net'
SCA_api_url = 'https://eu.api-sca.checkmarx.net'
SCA_auth_url = 'https://eu.platform.checkmarx.net/identity/connect/token'

proxy_servers = {
   'https': SCA_proxy
}

#########################################
# SAST Portal Configuration:
#########################################

# SAST has separate credentials from SCA
SAST_username = 'admin'  
SAST_password = 'Aa12345678!'  
SAST_server_name = '123http://ec2-35-167-1-96.us-west-2.compute.amazonaws.com'

# SAST Proxy (separate from SCA proxy)
SAST_proxy = ''  # Leave empty if no proxy needed

SAST_proxy_servers = {
   'https': SAST_proxy
}

# SAST API URLs (constructed from server name)
SAST_auth_url = f"{SAST_server_name}/CxRestAPI/auth/identity/connect/token"
SAST_api_url = f"{SAST_server_name}/CxRestAPI"

#########################################
# Analysis Configuration:
#########################################

# Define a global list of restricted licenses
RESTRICTED_LICENSES = ["AGPL", "GPL"]

# Global setting for removing dev dependencies from analysis
REMOVE_DEV_DEPENDENCIES = True

# Global setting for minimum risk score threshold
RISK_SCORE_THRESHOLD = 7.0

#########################################

def SCA_get_access_token():
    """Get authentication token from SCA portal"""
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
        response.raise_for_status()
        access_token = response.json()['access_token']
        return access_token
    except requests.RequestException as e:
        print("Exception: Failed to get access token:", str(e))
        return ""

def SAST_get_access_token():
    """Get authentication token for SAST API (uses separate credentials from SCA)"""
    try:
        payload = {
            'scope': 'access_control_api sast_api',
            'client_id': 'resource_owner_sast_client',
            'grant_type': 'password',
            'client_secret': '014DF517-39D1-4453-B7B3-9930C563627C',
            'username': SAST_username,
            'password': SAST_password
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(SAST_auth_url, headers=headers, data=payload, verify=False, proxies=SAST_proxy_servers)
        response.raise_for_status()
        access_token = response.json()['access_token']
        print("Successfully authenticated to SAST API")
        return access_token
    except requests.RequestException as e:
        print(f"Exception: Failed to get SAST access token: {str(e)}")
        print(f"Make sure SAST credentials and server name are configured correctly")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        return ""

def SAST_get_all_projects(access_token=""):
    """Get all SAST projects"""
    if not access_token:
        access_token = SAST_get_access_token()
        
    if not access_token:
        return []
    
    try:
        url = f"{SAST_api_url}/projects"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers, proxies=SAST_proxy_servers, verify=False)
        response.raise_for_status()
        projects = response.json()
        
        if isinstance(projects, list):
            print(f"Retrieved {len(projects)} SAST projects from API")
            return projects
        elif isinstance(projects, dict):
            # Handle different response formats
            project_list = projects.get('projects', projects.get('value', []))
            print(f"Retrieved {len(project_list)} SAST projects from API")
            return project_list
        
        return []
        
    except Exception as e:
        print(f"Exception getting SAST projects: {str(e)}")
        traceback.print_exc()
        return []

def SAST_get_project_details(project_id, access_token=""):
    """Get SAST project details including team information"""
    if not access_token:
        access_token = SAST_get_access_token()
        
    if not access_token:
        return None
    
    try:
        url = f"{SAST_api_url}/projects/{project_id}"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers, proxies=SAST_proxy_servers, verify=False)
        response.raise_for_status()
        project_details = response.json()
        
        return project_details
        
    except Exception as e:
        print(f"  Exception getting SAST project details for {project_id}: {str(e)}")
        return None

def SAST_get_team_name(team_id, access_token=""):
    """Get SAST team name by team ID"""
    if not access_token:
        access_token = SAST_get_access_token()
        
    if not access_token:
        return None
    
    try:
        url = f"{SAST_api_url}/auth/teams/{team_id}"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers, proxies=SAST_proxy_servers, verify=False)
        response.raise_for_status()
        team_details = response.json()
        
        # Try different possible field names for team name
        team_name = (
            team_details.get('name') or
            team_details.get('fullName') or
            team_details.get('teamName')
        )
        
        return team_name
        
    except Exception as e:
        print(f"  Exception getting SAST team name for team ID {team_id}: {str(e)}")
        return None

def SAST_get_project_last_scan_id(project_id, access_token=""):
    """Get the last scan ID for a SAST project"""
    if not access_token:
        access_token = SAST_get_access_token()
        
    if not access_token:
        return None
    
    try:
        url = f"{SAST_api_url}/sast/scans"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        params = {
            'projectId': project_id,
            'last': 1
        }
        
        response = requests.get(url, headers=headers, params=params, proxies=SAST_proxy_servers, verify=False)
        response.raise_for_status()
        scans = response.json()
        
        if isinstance(scans, list) and len(scans) > 0:
            return scans[0].get('id')
        
        return None
        
    except Exception as e:
        print(f"Exception getting last SAST scan for project {project_id}: {str(e)}")
        return None

def SAST_download_scan_report(scan_id, report_type='CSV', access_token=""):
    """Download SAST scan report"""
    if not access_token:
        access_token = SAST_get_access_token()
        
    if not access_token:
        return None
    
    try:
        # Register report
        url = f"{SAST_api_url}/reports/sastScan"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'reportType': report_type,
            'scanId': scan_id
        }
        
        response = requests.post(url, headers=headers, json=payload, proxies=SAST_proxy_servers, verify=False)
        response.raise_for_status()
        report_data = response.json()
        report_id = report_data.get('reportId')
        
        if not report_id:
            print(f"Failed to generate report for scan {scan_id}")
            return None
        
        # Wait for report to be ready
        status_url = f"{SAST_api_url}/reports/sastScan/{report_id}/status"
        max_attempts = 30
        attempt = 0
        
        while attempt < max_attempts:
            status_response = requests.get(status_url, headers=headers, proxies=SAST_proxy_servers, verify=False)
            status_response.raise_for_status()
            status_data = status_response.json()
            
            status = status_data.get('status', {}).get('value')
            
            if status == 'Created':
                # Download report
                download_url = f"{SAST_api_url}/reports/sastScan/{report_id}"
                download_response = requests.get(download_url, headers=headers, proxies=SAST_proxy_servers, verify=False)
                download_response.raise_for_status()
                
                return download_response.content
            
            elif status == 'Failed':
                print(f"Report generation failed for scan {scan_id}")
                return None
            
            # Wait and retry
            time.sleep(2)
            attempt += 1
        
        print(f"Report generation timeout for scan {scan_id}")
        return None
        
    except Exception as e:
        print(f"Exception downloading SAST report for scan {scan_id}: {str(e)}")
        traceback.print_exc()
        return None

def parse_sast_csv_report(csv_content):
    """
    Parse SAST CSV report and aggregate vulnerabilities by type and severity
    
    Returns: Dictionary with (vuln_type, severity) -> count
    """
    try:
        from io import StringIO
        
        # Parse CSV
        df = pd.read_csv(StringIO(csv_content.decode('utf-8')))
        
        # Debug: print column names
        # print(f"  CSV columns: {list(df.columns)[:5]}...")  # Show first 5 columns
        
        # Aggregate by vulnerability type (Query) and Result Severity
        vulnerability_summary = {}
        
        # Check for possible column name variations
        query_col = None
        severity_col = None
        
        # Find Query column (vulnerability type)
        for col in df.columns:
            if 'query' in col.lower():
                query_col = col
                break
        
        # Find Severity column
        for col in df.columns:
            if 'severity' in col.lower():
                severity_col = col
                break
        
        if not query_col:
            print(f"  Warning: Could not find Query column in CSV")
            return {}
        
        if not severity_col:
            print(f"  Warning: Could not find Severity column in CSV")
            return {}
        
        print(f"  Using columns: Query='{query_col}', Severity='{severity_col}'")
        
        # Aggregate vulnerabilities
        for _, row in df.iterrows():
            vuln_type = str(row[query_col])
            severity = str(row[severity_col]).upper()
            
            # Skip empty rows
            if pd.isna(vuln_type) or vuln_type == 'nan':
                continue
            
            key = (vuln_type, severity)
            
            if key not in vulnerability_summary:
                vulnerability_summary[key] = 0
            
            vulnerability_summary[key] += 1
        
        return vulnerability_summary
        
    except Exception as e:
        print(f"  Exception parsing SAST CSV: {str(e)}")
        traceback.print_exc()
        return {}

def fetch_sast_results_from_api(risk_score_threshold=None):
    """
    Fetch SAST results from Checkmarx SAST API for all projects
    Downloads CSV reports and aggregates vulnerabilities
    
    Args:
        risk_score_threshold: Minimum risk score threshold
    
    Returns:
        List of SAST results formatted for All Results sheet
    """
    print("\n" + "="*80)
    print("FETCHING SAST RESULTS FROM API")
    print("="*80)
    
    # Get SAST access token
    sast_token = SAST_get_access_token()
    if not sast_token:
        print("Failed to get SAST access token - skipping SAST results")
        return []
    
    # Get all SAST projects
    sast_projects = SAST_get_all_projects(sast_token)
    if not sast_projects:
        print("No SAST projects found")
        return []
    
    print(f"Found {len(sast_projects)} SAST projects")
    
    # Severity to Risk Score mapping
    severity_to_risk_score = {
        'HIGH': 8.5,
        'MEDIUM': 6.0,
        'LOW': 4.0,
        'INFO': 0.0,
        'INFORMATION': 0.0
    }
    
    all_sast_results = []
    projects_with_sast = 0
    projects_without_sast = 0
    
    for i, project in enumerate(sast_projects, 1):
        project_name = project.get('name', 'Unknown')
        project_id = project.get('id')
        
        if not project_id:
            continue
        
        print(f"\n[{i}/{len(sast_projects)}] Processing SAST for project: {project_name}")
        
        # Get project details for team information
        project_team = None
        project_details = SAST_get_project_details(project_id, sast_token)
        if project_details:
            # Get team ID from project details
            team_id = (
                project_details.get('teamId') or 
                project_details.get('team') or
                project_details.get('owningTeam')
            )
            
            if team_id:
                # Get team name from team ID
                project_team = SAST_get_team_name(team_id, sast_token)
                if project_team:
                    print(f"  Team: {project_team}")
                else:
                    # If team name API fails, use team ID as fallback
                    project_team = str(team_id)
                    print(f"  Team ID: {project_team}")
        
        # Get last scan ID
        scan_id = SAST_get_project_last_scan_id(project_id, sast_token)
        if not scan_id:
            print(f"  No SAST scans found for: {project_name}")
            projects_without_sast += 1
            continue
        
        print(f"  Latest scan ID: {scan_id}")
        
        # Download CSV report
        csv_content = SAST_download_scan_report(scan_id, 'CSV', sast_token)
        if not csv_content:
            print(f"  Failed to download report")
            projects_without_sast += 1
            continue
        
        # Parse CSV and aggregate vulnerabilities
        vulnerability_summary = parse_sast_csv_report(csv_content)
        
        if not vulnerability_summary:
            print(f"  No vulnerabilities found in report")
            projects_without_sast += 1
            continue
        
        projects_with_sast += 1
        vuln_count = 0
        
        # Convert to All Results format
        for (vuln_type, severity), count in vulnerability_summary.items():
            risk_score = severity_to_risk_score.get(severity, 0.0)
            
            # Apply risk score threshold
            if risk_score_threshold is not None and risk_score <= risk_score_threshold:
                continue
            
            # Don't show CxServer SAST team name - leave cell empty
            display_team = '' if project_team == 'CxServer' else project_team
            
            all_sast_results.append({
                'Project': project_name,
                'Team': display_team,
                'Vulnerability/ Package': vuln_type,
                'Version': 'N/A',
                'ReleaseDate': 'N/A',
                'Licenses': 'N/A',
                'NewestVersion': 'N/A',
                'NewestVersionReleaseDate': 'N/A',
                'RiskScore': risk_score,
                'PackageRepository': 'N/A',
                'DependencyType': 'N/A',
                'IssueType': 'SAST Vulnerbility',
                'count': count
            })
            vuln_count += count
        
        print(f"  Found {vuln_count} SAST vulnerabilities")
    
    print("\n" + "="*80)
    print(f"SAST API FETCH SUMMARY")
    print("="*80)
    print(f"Projects with SAST results: {projects_with_sast}")
    print(f"Projects without SAST: {projects_without_sast}")
    print(f"Total SAST vulnerability records: {len(all_sast_results)}")
    print("="*80)
    
    return all_sast_results

def SCA_get_all_projects(access_token=""):
    """Get all projects from SCA portal"""
    if not access_token:
        access_token = SCA_get_access_token()

    url = SCA_api_url + "/risk-management/projects"

    try:
        headers = {
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.get(url, headers=headers, proxies=proxy_servers, verify=False)
        response.raise_for_status()
        response_json = response.json()
        
        projects = []
        if isinstance(response_json, list):
            projects = response_json
        elif 'projects' in response_json:
            projects = response_json['projects']
        else:
            print("Unexpected response format when fetching projects")
            return []
        
        print(f"Retrieved {len(projects)} total projects from API")
        return projects
        
    except Exception as e:
        print("Exception: SCA_get_all_projects:", str(e))
        traceback.print_exc()
        return []

def SCA_get_project_latest_scan_id(project_name, access_token=""):
    """Get the latest scan ID for a project"""
    if not access_token:
        access_token = SCA_get_access_token()

    url = SCA_api_url + "/risk-management/projects?name=" + project_name

    try:
        headers = {
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.get(url, headers=headers, proxies=proxy_servers, verify=False)
        response.raise_for_status()
        response_json = response.json()
        
        if 'latestScanId' in response_json:
            return response_json['latestScanId']
        else:
            print(f"No scans found for project: {project_name}")
            return ""
    except Exception as e:
        print("Exception: SCA_get_project_latest_scan_id:", str(e))
        return ""

def SCA_get_project_details(project_id, access_token=""):
    """
    Get project details including team information
    
    The project details API may return fields like:
    - team: Team name
    - teamName: Alternative field name for team
    - tags: Project tags
    - assignedTeams: List of assigned teams
    """
    if not access_token:
        access_token = SCA_get_access_token()

    url = SCA_api_url + "/risk-management/projects/" + project_id

    try:
        headers = {
            'Authorization': 'Bearer ' + access_token
        }

        response = requests.get(url, headers=headers, proxies=proxy_servers, verify=False)
        response.raise_for_status()
        response_json = response.json()
        
        return response_json
    except Exception as e:
        print(f"Exception: SCA_get_project_details for project_id {project_id}:", str(e))
        return {}


def SCA_get_report(project_name, report_type='csv', access_token=""):
    """Download the report from SCA portal"""
    if not access_token:
        access_token = SCA_get_access_token()

    scan_id = SCA_get_project_latest_scan_id(project_name, access_token)
    if scan_id:
        try:
            url = SCA_api_url + "/risk-management/risk-reports/" + scan_id + '/' + 'export?format=' + report_type + '&dataType[]=All'
        
            headers = {
                'Authorization': 'Bearer ' + access_token
            }

            print(f"Downloading {report_type.upper()} report for project: {project_name}")
            response = requests.get(url, headers=headers, proxies=proxy_servers, verify=False)
            response.raise_for_status()
            
            report_content = response.content
            if report_type.lower() == 'csv':
                report_path = os.path.join(os.getcwd(), project_name + '_SCA_report.zip')
            else:    
                report_path = os.path.join(os.getcwd(), project_name + '_SCA_report.' + report_type)
            
            with open(report_path, 'wb') as f:
                f.write(report_content)
            
            print(f"Report downloaded successfully: {report_path}")
            return report_path
        except Exception as e:
            print("Exception: SCA_get_report", str(e))
            traceback.print_exc()
            return ""
    else:
        print(f"Could not find scan ID for project: {project_name}")
        return ""

def parse_risk_score(risk_score_value):
    """Parse risk score value and return a float or None if invalid/N/A"""
    if risk_score_value is None or str(risk_score_value).upper() in ['N/A', 'NAN', '']:
        return None
    
    try:
        return float(risk_score_value)
    except (ValueError, TypeError):
        return None

def analyze_report_from_zip(report_zip_path, project_name, show_all_severities=False, show_transitive=True, risk_score_threshold=None, show_dev_dependencies=True, team=None):
    """Analyze an existing SCA report (zip file containing CSV reports)"""
    try:
        if not os.path.exists(report_zip_path):
            print(f"Error: Report file not found: {report_zip_path}")
            return [], [], []

        csv_filename = 'Packages.csv'
        extracted_data = {}

        print(f"\nAnalyzing report: {report_zip_path}")

        try:
            with zipfile.ZipFile(report_zip_path, 'r') as zip_ref:
                print(f"Files in zip: {zip_ref.namelist()}")
                
                if csv_filename not in zip_ref.namelist():
                    print(f"Error: {csv_filename} not found in zip file")
                    return [], [], []
                
                with zip_ref.open(csv_filename) as csv_file:
                    extracted_data[csv_filename] = pd.read_csv(csv_file)

            if csv_filename in extracted_data:
                packages_df = extracted_data[csv_filename]
                print(f"Total packages in report: {len(packages_df)}")

                required_columns = {'Severity', 'IsDirectDependency', 'Licenses'}
                if not required_columns.issubset(packages_df.columns):
                    print(f"Warning: Required columns not found in CSV")
                    print(f"Available columns: {list(packages_df.columns)}")
                    return [], [], []
                
                # Check for additional dependency type columns
                has_dependency_type = 'DependencyType' in packages_df.columns
                if has_dependency_type:
                    print("DependencyType column found")
                    print(f"Unique dependency types: {packages_df['DependencyType'].unique()}")

                packages_df['Severity'] = packages_df['Severity'].astype(str).str.lower()
                packages_df['Licenses'] = packages_df['Licenses'].astype(str)
                
                has_risk_score = 'RiskScore' in packages_df.columns
                if has_risk_score:
                    packages_df['RiskScore'] = packages_df['RiskScore'].fillna('N/A')
                    print("RiskScore column found")
                else:
                    print("RiskScore column not found - will use 'N/A'")

                has_dev_flag = 'IsDevelopmentDependency' in packages_df.columns
                has_test_flag = 'IsTestDependency' in packages_df.columns
                
                if has_dev_flag:
                    print("IsDevelopmentDependency column found")
                if has_test_flag:
                    print("IsTestDependency column found")

                has_release_date = 'ReleaseDate' in packages_df.columns
                has_newest_version = 'NewestVersion' in packages_df.columns
                has_newest_release_date = 'NewestLibraryDate' in packages_df.columns
                
                # Check for alternative column names
                if not has_newest_release_date:
                    if 'NewestVersionReleaseDate' in packages_df.columns:
                        has_newest_release_date = True
                        newest_date_column = 'NewestVersionReleaseDate'
                    elif 'LatestVersionDate' in packages_df.columns:
                        has_newest_release_date = True
                        newest_date_column = 'LatestVersionDate'
                    elif 'NewestLibraryReleaseDate' in packages_df.columns:
                        has_newest_release_date = True
                        newest_date_column = 'NewestLibraryReleaseDate'
                    else:
                        newest_date_column = None
                else:
                    newest_date_column = 'NewestLibraryDate'
                
                has_package_repository = 'PackageRepository' in packages_df.columns
                
                # Debug output for column detection
                if not has_newest_release_date:
                    print(f"Warning: Newest version date column not found. Available columns: {list(packages_df.columns)}")
                else:
                    print(f"Using column '{newest_date_column}' for newest version release date")

                if risk_score_threshold is not None:
                    print(f"Risk score filtering: > {risk_score_threshold}")
                else:
                    print("Risk score filtering: Disabled")
                
                if not show_dev_dependencies:
                    print("Dev dependencies: Excluded")
                else:
                    print("Dev dependencies: Included")

                vulnerabilities = []
                license_issues = []
                results_data = []
                dev_packages_skipped = 0

                for _, row in packages_df.iterrows():
                    package_name = row['Name']
                    package_version = row['Version']
                    is_direct = row['IsDirectDependency']
                    
                    # Determine dependency type - check for Mixed dependencies (without parentheses)
                    if has_dependency_type:
                        dep_type_from_column = str(row['DependencyType']).lower()
                        if dep_type_from_column in ['direct', 'mixed']:
                            dependency_type = dep_type_from_column
                            is_non_transitive = True
                        else:
                            dependency_type = "transitive"
                            is_non_transitive = False
                    else:
                        # Fallback to IsDirectDependency boolean
                        dependency_type = "direct" if is_direct else "transitive"
                        is_non_transitive = is_direct
                    
                    risk_score = row['RiskScore'] if has_risk_score else 'N/A'
                    severity = row['Severity']
                    
                    is_dev = False
                    if has_dev_flag and row['IsDevelopmentDependency']:
                        is_dev = True
                    if has_test_flag and row['IsTestDependency']:
                        is_dev = True
                    
                    if not show_dev_dependencies and is_dev:
                        dev_packages_skipped += 1
                        continue
                    
                    if is_dev:
                        dependency_type += " [dev]"
                    
                    # Modified logic: when --direct_only is used, include both Direct and Mixed
                    if not show_transitive and not is_non_transitive:
                        continue
                    
                    parsed_risk_score = parse_risk_score(risk_score)
                    if risk_score_threshold is not None and parsed_risk_score is not None:
                        if parsed_risk_score <= risk_score_threshold:
                            continue
                    
                    licenses = row['Licenses']
                    license_risk = None
                    for restricted in RESTRICTED_LICENSES:
                        if restricted.upper() in licenses.upper():
                            license_risk = f"{restricted} License"
                            break
                    
                    package_age_days = None
                    package_age_text = ""
                    
                    if has_release_date and pd.notna(row['ReleaseDate']):
                        try:
                            release_date = pd.to_datetime(row['ReleaseDate'])
                            today = pd.Timestamp.now()
                            package_age_days = (today - release_date).days
                            package_age_text = f"{package_age_days} days old"
                        except Exception as e:
                            package_age_text = "Unknown"
                    
                    is_outdated = False
                    if has_newest_version and pd.notna(row['NewestVersion']):
                        if str(row['NewestVersion']) != str(package_version):
                            is_outdated = True
                    
                    if has_newest_release_date and pd.notna(row[newest_date_column]):
                        try:
                            newest_release_date = pd.to_datetime(row[newest_date_column])
                            today = pd.Timestamp.now()
                            newest_age_days = (today - newest_release_date).days
                        except:
                            newest_age_days = None
                    else:
                        newest_age_days = None
                    
                    package_repository = row['PackageRepository'] if has_package_repository else 'N/A'
                    
                    if severity not in ['none', 'info']:
                        if show_all_severities or severity == 'high':
                            vulnerabilities.append({
                                'package': f"{package_name} {package_version} {dependency_type}",
                                'severity': severity,
                                'risk_score': risk_score,
                                'license_risk': license_risk,
                                'licenses': licenses,
                                'is_outdated': is_outdated,
                                'package_age_days': package_age_days
                            })
                            
                            if license_risk:
                                issue_type = "Vulnerability & License"
                            else:
                                issue_type = "Vulnerability"
                            
                            # Get release dates
                            release_date = row['ReleaseDate'] if has_release_date and pd.notna(row['ReleaseDate']) else 'N/A'
                            newest_version = row['NewestVersion'] if has_newest_version and pd.notna(row['NewestVersion']) else 'N/A'
                            newest_release_date = 'N/A'
                            if has_newest_release_date and pd.notna(row[newest_date_column]):
                                newest_release_date = row[newest_date_column]
                            
                            results_data.append({
                                'Project': project_name,
                                'Team': team,
                                'Vulnerability/ Package': package_name,
                                'Version': package_version,
                                'ReleaseDate': release_date,
                                'Licenses': licenses,
                                'NewestVersion': newest_version,
                                'NewestVersionReleaseDate': newest_release_date,
                                'RiskScore': risk_score,
                                'PackageRepository': package_repository,
                                'DependencyType': dependency_type,
                                'IssueType': 'SCA ' + issue_type,
                                'count': None  # SCA doesn't have count field
                            })
                    
                    if license_risk:
                        license_issues.append({
                            'package': f"{package_name} {package_version} {dependency_type}",
                            'license_risk': license_risk,
                            'licenses': licenses,
                            'severity': severity
                        })
                        
                        if severity in ['none', 'info']:
                            # Get release dates for license-only issues
                            release_date = row['ReleaseDate'] if has_release_date and pd.notna(row['ReleaseDate']) else 'N/A'
                            newest_version = row['NewestVersion'] if has_newest_version and pd.notna(row['NewestVersion']) else 'N/A'
                            newest_release_date = 'N/A'
                            if has_newest_release_date and pd.notna(row[newest_date_column]):
                                newest_release_date = row[newest_date_column]
                            
                            results_data.append({
                                'Project': project_name,
                                'Team': team,
                                'Vulnerability/ Package': package_name,
                                'Version': package_version,
                                'ReleaseDate': release_date,
                                'Licenses': licenses,
                                'NewestVersion': newest_version,
                                'NewestVersionReleaseDate': newest_release_date,
                                'RiskScore': risk_score,
                                'PackageRepository': package_repository,
                                'DependencyType': dependency_type,
                                'IssueType': 'SCA License',
                                'count': None  # SCA doesn't have count field
                            })
                
                if dev_packages_skipped > 0:
                    print(f"Skipped {dev_packages_skipped} dev/test packages")
                
                print(f"\nVulnerabilities found: {len(vulnerabilities)}")
                print(f"License issues found: {len(license_issues)}")
                
                for vuln in vulnerabilities:
                    print(f"  [{vuln['severity'].upper()}] {vuln['package']} | Risk: {vuln['risk_score']}")
                    if vuln['license_risk']:
                        print(f"    ⚠ {vuln['license_risk']}: {vuln['licenses']}")
                
                for lic in license_issues:
                    if lic['severity'] in ['none', 'info']:
                        print(f"  [LICENSE] {lic['package']} | {lic['license_risk']}: {lic['licenses']}")
                
                return vulnerabilities, license_issues, results_data

        except zipfile.BadZipFile:
            print(f"Error: {report_zip_path} is not a valid zip file")
            return [], [], []

    except Exception as e:
        print(f"Error analyzing report: {str(e)}")
        traceback.print_exc()
        return [], [], []

def calculate_risk_summary(combined_results):
    """
    Calculate project risk summary from combined SCA and SAST results
    
    Args:
        combined_results: List of all results (SCA + SAST combined)
    
    Returns:
        List of risk summary dictionaries per project
    """
    # Group by project
    projects = {}
    for record in combined_results:
        project_name = record.get('Project', 'Unknown')
        if project_name not in projects:
            projects[project_name] = []
        projects[project_name].append(record)
    
    # Calculate risk summary for each project
    risk_summary_data = []
    for project_name, records in projects.items():
        # High risk is >= 8.0
        high_risk_vulnerabilities = []
        for r in records:
            risk_score = parse_risk_score(r.get('RiskScore', 'N/A'))
            if risk_score is not None and risk_score >= 8.0:
                high_risk_vulnerabilities.append(r)
        
        high_risk_count = len(high_risk_vulnerabilities)
        
        avg_high_risk_score = 0.0
        if high_risk_vulnerabilities:
            risk_scores = [parse_risk_score(r.get('RiskScore')) for r in high_risk_vulnerabilities]
            risk_scores = [rs for rs in risk_scores if rs is not None]
            if risk_scores:
                avg_high_risk_score = round(sum(risk_scores) / len(risk_scores), 1)
        
        risk_summary_data.append({
            'projectName': project_name,
            'High_Risk_Count': high_risk_count,
            'Avg_High_Risk_Score': avg_high_risk_score
        })
    
    return risk_summary_data

def export_to_excel_with_summary(all_results_data, risk_summary_data, output_file, risk_score_threshold=None):
    """Export results to Excel with multiple sheets, combining SCA and SAST in All Vulnerabilities sheet"""
    try:
        # Load SAST results from file or API
        sast_results = []
        
        # Fetch from API - gets ALL SAST projects independently
        sast_results = fetch_sast_results_from_api(risk_score_threshold)
        
        # Combine SCA and SAST results
        combined_results = all_results_data.copy()
        if sast_results:
            combined_results.extend(sast_results)
            print(f"\nCombined {len(all_results_data)} SCA results with {len(sast_results)} SAST results")
            print(f"Total results: {len(combined_results)}")
        
        # Recalculate risk summary with combined SCA + SAST data
        risk_summary_data = calculate_risk_summary(combined_results)
        print(f"Calculated risk summary for {len(risk_summary_data)} projects (including SAST)")
        
        # Create Excel writer
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            # Write combined results sheet (SCA + SAST)
            if combined_results:
                results_df = pd.DataFrame(combined_results)
                results_df.to_excel(writer, sheet_name='All Results', index=False)
                print(f"Exported {len(combined_results)} records to 'All Results' sheet")
                
                # Show breakdown by issue type
                if 'IssueType' in results_df.columns:
                    issue_type_counts = results_df['IssueType'].value_counts()
                    print("\nBreakdown by Issue Type:")
                    for issue_type, count in issue_type_counts.items():
                        print(f"  {issue_type}: {count}")
            
            # Write project risk summary sheet
            if risk_summary_data:
                summary_df = pd.DataFrame(risk_summary_data)
                # Sort by High_Risk_Count descending
                summary_df = summary_df.sort_values('High_Risk_Count', ascending=False)
                
                # Filter out projects with 0 vulnerabilities
                original_count = len(summary_df)
                summary_df = summary_df[summary_df['High_Risk_Count'] > 0]
                filtered_count = original_count - len(summary_df)
                
                if filtered_count > 0:
                    print(f"Excluded {filtered_count} project(s) with 0 vulnerabilities from risk summary")
                
                summary_df.to_excel(writer, sheet_name='Project Risk Summary', index=False)
                print(f"Exported {len(summary_df)} projects to 'Project Risk Summary' sheet")
                
                # Add bar chart to the risk summary sheet (only if there are projects to show)
                if len(summary_df) > 0:
                    workbook = writer.book
                    worksheet = writer.sheets['Project Risk Summary']
                    
                    from openpyxl.chart import BarChart, Reference
                    
                    # Limit chart to top 10 projects
                    chart_rows = min(10, len(summary_df))
                    
                    # Create a bar chart
                    chart = BarChart()
                    chart.type = "col"  # Column chart (vertical bars)
                    chart.style = 10
                    chart.title = f"Top {chart_rows} Highest Risk Projects"
                    chart.y_axis.title = 'High Risk Vulnerability Count'
                    chart.x_axis.title = 'Project'
                    
                    # Define data range for the chart (top 10 only)
                    # Data starts at row 2 (after header), column 2 is High_Risk_Count
                    data = Reference(worksheet, min_col=2, min_row=1, max_row=chart_rows + 1)
                    categories = Reference(worksheet, min_col=1, min_row=2, max_row=chart_rows + 1)
                    
                    chart.add_data(data, titles_from_data=True)
                    chart.set_categories(categories)
                    chart.shape = 4
                    
                    # Set chart size
                    chart.height = 15  # default is 7.5
                    chart.width = 20   # default is 15
                    
                    # Position the chart to the right of the data (column E, row 2)
                    worksheet.add_chart(chart, "E2")
                    
                    print(f"Added bar chart showing top {chart_rows} highest risk projects")
            
            # Create Vulnerability Summary sheet (SCA and SAST combined)
            if combined_results:
                # Filter vulnerability records - exclude License-only (handles typo in SAST: "Vulnerbility")
                vuln_data = [r for r in combined_results if r.get('IssueType', '') != 'SCA License']
                
                if vuln_data:
                    # Group by package/vulnerability name
                    package_stats = {}
                    for record in vuln_data:
                        package_name = record.get('Vulnerability/ Package', 'Unknown')
                        risk_score = parse_risk_score(record.get('RiskScore'))
                        
                        if package_name not in package_stats:
                            package_stats[package_name] = {
                                'occurrences': 0,
                                'risk_scores': []
                            }
                        
                        package_stats[package_name]['occurrences'] += 1
                        if risk_score is not None:
                            package_stats[package_name]['risk_scores'].append(risk_score)
                    
                    # Create vulnerability summary data
                    vuln_summary = []
                    for package_name, stats in package_stats.items():
                        avg_risk = sum(stats['risk_scores']) / len(stats['risk_scores']) if stats['risk_scores'] else 0
                        vuln_summary.append({
                            'Package / vulnerability': package_name,
                            'Number of Occurrences': stats['occurrences'],
                            'Average Risk Score': round(avg_risk, 2)
                        })
                    
                    # Create DataFrame and sort by occurrences (high to low)
                    vuln_summary_df = pd.DataFrame(vuln_summary)
                    vuln_summary_df = vuln_summary_df.sort_values('Number of Occurrences', ascending=False)
                    
                    # Write to Excel
                    vuln_summary_df.to_excel(writer, sheet_name='Vulnerability Summary', index=False)
                    print(f"Exported {len(vuln_summary_df)} packages/vulnerabilities to 'Vulnerability Summary' sheet")
                    
                    # Add bar chart for top 10 vulnerable packages
                    from openpyxl.chart import BarChart, Reference
                    
                    workbook = writer.book
                    vuln_worksheet = writer.sheets['Vulnerability Summary']
                    
                    # Limit chart to top 10 packages
                    chart_rows = min(10, len(vuln_summary_df))
                    
                    # Create a bar chart
                    vuln_chart = BarChart()
                    vuln_chart.type = "col"
                    vuln_chart.style = 11
                    vuln_chart.title = f"Top {chart_rows} Most Common Vulnerabilities"
                    vuln_chart.y_axis.title = 'Number of Occurrences'
                    vuln_chart.x_axis.title = 'Package / Vulnerability'
                    
                    # Define data range for the chart
                    # Column 2 is Number of Occurrences
                    data = Reference(vuln_worksheet, min_col=2, min_row=1, max_row=chart_rows + 1)
                    categories = Reference(vuln_worksheet, min_col=1, min_row=2, max_row=chart_rows + 1)
                    
                    vuln_chart.add_data(data, titles_from_data=True)
                    vuln_chart.set_categories(categories)
                    vuln_chart.shape = 4
                    
                    # Set chart size
                    vuln_chart.height = 15
                    vuln_chart.width = 20
                    
                    # Position the chart to the right of the data (column E, row 2)
                    vuln_worksheet.add_chart(vuln_chart, "E2")
                    
                    print(f"Added bar chart showing top {chart_rows} most common vulnerabilities")
        
        print(f"\nResults exported to Excel: {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting to Excel: {e}")
        traceback.print_exc()
        return False

def analyze_all_projects(show_all_severities=False, show_transitive=True, keep_report=False, risk_score_threshold=None, show_dev_dependencies=True, output_csv=None, delay_between_projects=0.1):
    """Analyze all projects in the SCA portal"""
    try:
        print("Fetching all projects from SCA portal...")
        access_token = SCA_get_access_token()
        if not access_token:
            print("Failed to get access token")
            return 1
        
        projects = SCA_get_all_projects(access_token)
        
        if not projects:
            print("No projects found")
            return 1
        
        # Filter out projects with nexus_sca prefix
        original_count = len(projects)
        projects = [p for p in projects if not p.get('name', '').lower().startswith('nexus_sca')]
        excluded_count = original_count - len(projects)
        
        if excluded_count > 0:
            print(f"Excluded {excluded_count} project(s) with 'nexus_sca' prefix")
        
        if not projects:
            print("No projects remaining after filtering")
            return 1
        
        print(f"Found {len(projects)} projects to analyze\n")
        
        all_results_data = []
        risk_summary_data = []  # New: Track risk summary per project
        total_vulnerabilities = 0
        total_license_issues = 0
        successful_projects = 0
        failed_projects = 0
        
        for i, project in enumerate(projects, 1):
            project_name = project.get('name', 'Unknown')
            project_id = project.get('id', '')
            
            # Fetch project details to get team information
            project_team = None
            if project_id:
                project_details = SCA_get_project_details(project_id, access_token)
                
                # Try different possible field names for team
                project_team = project_details.get('team') or project_details.get('teamName')
                
                # If not found, try assignedTeams list
                if not project_team:
                    assigned_teams = project_details.get('assignedTeams', [])
                    if isinstance(assigned_teams, list) and len(assigned_teams) > 0:
                        project_team = assigned_teams[0]
                
                # If team is a dictionary, try to get the name field
                if isinstance(project_team, dict):
                    project_team = project_team.get('name') or project_team.get('teamName')
                
                # Remove /CxServer/ prefix from team name
                if project_team and isinstance(project_team, str):
                    if project_team.startswith('/CxServer/'):
                        project_team = project_team.replace('/CxServer/', '', 1)
            
            print(f"\n{'='*80}")
            print(f"Analyzing project {i}/{len(projects)}: {project_name}")
            if project_team:
                print(f"Team: {project_team}")
            print(f"{'='*80}")
            
            try:
                report_file = SCA_get_report(project_name, 'csv', access_token)
                
                if not report_file:
                    print(f"Failed to download report for project: {project_name}")
                    failed_projects += 1
                    
                    # Add delay before next project (even after failure)
                    if i < len(projects) and delay_between_projects > 0:
                        print(f"Waiting {delay_between_projects} seconds before next project...")
                        time.sleep(delay_between_projects)
                    continue
                
                vulnerabilities, license_issues, results_data = analyze_report_from_zip(
                    report_file, 
                    project_name,
                    show_all_severities, 
                    show_transitive, 
                    risk_score_threshold, 
                    show_dev_dependencies,
                    team=project_team
                )
                
                total_vulnerabilities += len(vulnerabilities)
                total_license_issues += len(license_issues)
                successful_projects += 1
                
                # Add results to master list
                all_results_data.extend(results_data)
                
                # Note: Risk summary will be calculated after SAST is loaded and combined
                # This allows including both SCA and SAST in the project risk calculations
                
                # Clean up downloaded report if not keeping
                if not keep_report and os.path.exists(report_file):
                    os.remove(report_file)
                    print(f"Deleted report file: {report_file}")
                
                # Add delay between projects (except for the last one)
                if i < len(projects) and delay_between_projects > 0:
                    print(f"Waiting {delay_between_projects} seconds before next project...")
                    time.sleep(delay_between_projects)
                    
            except Exception as e:
                print(f"Error analyzing project {project_name}: {e}")
                traceback.print_exc()
                failed_projects += 1
                
                # Add delay even after errors (except for the last project)
                if i < len(projects) and delay_between_projects > 0:
                    print(f"Waiting {delay_between_projects} seconds before next project...")
                    time.sleep(delay_between_projects)
                continue
        
        print("\n" + "="*80)
        print("OVERALL ANALYSIS SUMMARY")
        print("="*80)
        print(f"Total projects analyzed: {successful_projects}/{len(projects)}")
        print(f"Failed projects: {failed_projects}")
        print(f"Total vulnerabilities found: {total_vulnerabilities}")
        print(f"Total license issues found: {total_license_issues}")
        print("="*80)
        
        if output_csv and all_results_data:
            try:
                # Check if output file should be Excel (xlsx) or CSV
                if output_csv.lower().endswith('.xlsx'):
                    export_to_excel_with_summary(
                        all_results_data, 
                        risk_summary_data, 
                        output_csv, 
                        risk_score_threshold
                    )
                else:
                    # Original CSV export
                    results_df = pd.DataFrame(all_results_data)
                    results_df.to_csv(output_csv, index=False, encoding='utf-8')
                    print(f"\nResults exported to CSV: {output_csv}")
                    print(f"Total records exported: {len(all_results_data)}")
                    
                    # Also create risk summary CSV if main output is CSV
                    if risk_summary_data:
                        summary_csv = output_csv.replace('.csv', '_risk_summary.csv')
                        summary_df = pd.DataFrame(risk_summary_data)
                        summary_df = summary_df.sort_values('High_Risk_Count', ascending=False)
                        summary_df.to_csv(summary_csv, index=False, encoding='utf-8')
                        print(f"Risk summary exported to: {summary_csv}")
            except Exception as e:
                print(f"Error exporting results: {e}")
                traceback.print_exc()
        elif output_csv and not all_results_data:
            print(f"\nNo results to export")
        
        return 0
        
    except Exception as e:
        print(f"Error analyzing all projects: {str(e)}")
        traceback.print_exc()
        return 1

def analyze_report(project_name=None, report_path=None, show_all_severities=False, show_transitive=True, keep_report=False, risk_score_threshold=None, show_dev_dependencies=True, output_csv=None):
    """Analyze a single SCA report"""
    try:
        if report_path:
            print(f"Using existing report file: {report_path}\n")
            report_file = report_path
            downloaded = False
            if not project_name:
                project_name = os.path.splitext(os.path.basename(report_path))[0].replace('_SCA_report', '')
        elif project_name:
            print(f"Downloading report for project: {project_name}\n")
            report_file = SCA_get_report(project_name, 'csv')
            if not report_file:
                print("Failed to download report from SCA portal")
                return 1
            downloaded = True
        else:
            print("Error: Either project_name or report_path must be provided")
            return 1

        vulnerabilities, license_issues, results_data = analyze_report_from_zip(
            report_file, 
            project_name,
            show_all_severities, 
            show_transitive, 
            risk_score_threshold, 
            show_dev_dependencies,
            team=None  # Team info not available for single project analysis
        )
        
        print("="*80)
        print("ANALYSIS COMPLETE")
        print("="*80)
        print(f"Total vulnerabilities found: {len(vulnerabilities)}")
        print(f"Total license issues found: {len(license_issues)}")
        print("="*80)
        
        if output_csv and results_data:
            try:
                results_df = pd.DataFrame(results_data)
                results_df.to_csv(output_csv, index=False, encoding='utf-8')
                print(f"\nResults exported to CSV: {output_csv}")
                print(f"Total records exported: {len(results_data)}")
            except Exception as e:
                print(f"Error exporting to CSV: {e}")
                traceback.print_exc()
        elif output_csv and not results_data:
            print(f"\nNo results to export to CSV")
        
        if downloaded and not keep_report and os.path.exists(report_file):
            os.remove(report_file)
            print(f"\nDownloaded report deleted: {report_file}")
        
        return 0
                    
    except Exception as e:
        print(f"Error analyzing report: {str(e)}")
        traceback.print_exc()
        return 1

def main():
    """Main entry point"""
    status = 0

    try:
        parser = argparse.ArgumentParser(
            description="SCA Report Analyzer - Download and analyze Checkmarx SCA reports"
        )
        
        source_group = parser.add_mutually_exclusive_group(required=True)
        source_group.add_argument("--project_name", help="Project name in SCA portal")
        source_group.add_argument("--report_path", help="Path to existing SCA report zip file")
        source_group.add_argument("--all_projects", action='store_true', help="Analyze all projects")
        
        parser.add_argument("--all_severities", action='store_true', help="Show all severity levels")
        parser.add_argument("--direct_only", action='store_true', help="Show only direct dependencies")
        parser.add_argument("--keep_report", action='store_true', help="Keep downloaded report file")
        parser.add_argument("--show_dev", action='store_true', help="Include dev dependencies")
        parser.add_argument("--risk_threshold", type=float, default=None, help="Minimum risk score threshold")
        parser.add_argument("--output_csv", type=str, default=None, help="Export results to CSV or Excel (.xlsx for Excel with risk summary sheet)")
        parser.add_argument("--delay", type=float, default=0.1, help="Delay between projects in seconds (default: 0.1)")

        args = parser.parse_args()

        project_name = args.project_name
        report_path = args.report_path
        all_projects = args.all_projects
        show_all_severities = args.all_severities
        show_transitive = not args.direct_only
        keep_report = args.keep_report
        show_dev_dependencies = args.show_dev
        risk_score_threshold = args.risk_threshold
        output_csv = args.output_csv
        delay_between_projects = args.delay

        global REMOVE_DEV_DEPENDENCIES
        global RISK_SCORE_THRESHOLD
        
        if not args.show_dev:
            show_dev_dependencies = not REMOVE_DEV_DEPENDENCIES
        
        if risk_score_threshold is None:
            risk_score_threshold = RISK_SCORE_THRESHOLD

        print("="*80)
        print("SCA REPORT ANALYZER")
        print("="*80)
        if all_projects:
            print(f"Mode: Analyze all projects")
            print(f"Delay between projects: {delay_between_projects} seconds")
        elif project_name:
            print(f"Project: {project_name}")
        else:
            print(f"Report: {report_path}")
        print(f"Show all severities: {show_all_severities}")
        print(f"Show transitive: {show_transitive}")
        print(f"Show dev: {show_dev_dependencies}")
        if risk_score_threshold is not None:
            print(f"Risk threshold: > {risk_score_threshold}")
        if output_csv:
            print(f"Output CSV: {output_csv}")
        print("="*80 + "\n")

        if all_projects:
            status = analyze_all_projects(
                show_all_severities=show_all_severities,
                show_transitive=show_transitive,
                keep_report=keep_report,
                risk_score_threshold=risk_score_threshold,
                show_dev_dependencies=show_dev_dependencies,
                output_csv=output_csv,
                delay_between_projects=delay_between_projects
            )
        else:
            status = analyze_report(
                project_name=project_name,
                report_path=report_path,
                show_all_severities=show_all_severities,
                show_transitive=show_transitive,
                keep_report=keep_report,
                risk_score_threshold=risk_score_threshold,
                show_dev_dependencies=show_dev_dependencies,
                output_csv=output_csv
            )

    except SystemExit as e:
        raise
    except Exception as e:
        print("Exception in main:", str(e))
        traceback.print_exc()
        sys.exit(1)
    finally:
        if status == 0:
            print("\nAnalysis completed successfully")
        else:
            print("\nAnalysis completed with errors")
        sys.exit(status)
            
if __name__ == '__main__':
   main()