#scan_lock.py
# -*- coding: utf-8 -*-

from datetime import timedelta
import datetime
import requests
import argparse
import sys
import time

# Ensure UTF-8 encoding for stdout on Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

########################################################
SAST_username = 'admin'
SAST_password = 'Aa12345678!'
SAST_server_name = 'http://ec2-35-167-1-96.us-west-2.compute.amazonaws.com'

# Proxy configuration (set to None to disable proxy)
HTTP_PROXY = None  # Example: 'http://proxy.company.com:8080'
HTTPS_PROXY = None  # Example: 'http://proxy.company.com:8080'

# Retry configuration for rate limiting
MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 2  # seconds
RETRY_BACKOFF_FACTOR = 2  # exponential backoff multiplier
REQUEST_DELAY = 0.1  # delay between requests to avoid rate limiting
#########################################################################

SAST_auth_url = f"{SAST_server_name}/CxRestAPI/auth/identity/connect/token"
SAST_api_url = f"{SAST_server_name}/CxRestAPI"

def safe_print(message):
    """Print message with fallback for Unicode errors"""
    try:
        print(message)
    except UnicodeEncodeError:
        # Fallback: encode to ASCII with backslashreplace
        print(message.encode('ascii', 'backslashreplace').decode('ascii'))

def get_proxies():
    """Return proxy configuration dictionary"""
    proxies = {}
    if HTTP_PROXY:
        proxies['http'] = HTTP_PROXY
    if HTTPS_PROXY:
        proxies['https'] = HTTPS_PROXY
    return proxies if proxies else None

def SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url):
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

        proxies = get_proxies()
        response = requests.post(SAST_auth_url, headers=headers, data=payload, verify=False, proxies=proxies)
        response.raise_for_status()
        access_token = response.json()['access_token']
        return access_token
    except requests.exceptions.RequestException as e:
        #print(f"Exception: get SAST access token failed: {e}")
        return ""

def SAST_get_projects(access_token, SAST_api_url):
    try:
        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        url = f'{SAST_api_url}/projects'

        proxies = get_proxies()
        response = requests.get(url, headers=headers, verify=False, proxies=proxies)
        response.raise_for_status()
        
        return response.json()
    except requests.exceptions.RequestException as e:
        #print(f"Exception: SAST_get_projects: {e}")
        return ""

def SAST_get_scans(access_token, SAST_api_url, project_id):
    url = f"{SAST_api_url}/sast/scans?projectId={project_id}"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    proxies = get_proxies()
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, verify=False, proxies=proxies)
            response.raise_for_status()
            
            # Add delay to avoid rate limiting on successful requests
            time.sleep(REQUEST_DELAY)
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:  # Rate limit error
                if attempt < MAX_RETRIES - 1:
                    retry_delay = INITIAL_RETRY_DELAY * (RETRY_BACKOFF_FACTOR ** attempt)
                    print(f"Rate limit hit for project ID {project_id}. Retrying in {retry_delay} seconds... (attempt {attempt + 1}/{MAX_RETRIES})")
                    time.sleep(retry_delay)
                else:
                    print(f"Warning: Failed to get scans for project ID {project_id} after {MAX_RETRIES} retries: {e}")
                    return []
            else:
                print(f"Warning: Failed to get scans for project ID {project_id}: {e}")
                return []
        except requests.exceptions.RequestException as e:
            print(f"Warning: Failed to get scans for project ID {project_id}: {e}")
            return []
    
    return []

def prepare_for_data_retention(unlock_all=False, lock_interval=90, project_name_filter=None, run_data_retention=False, num_scans_to_keep=None):

    if project_name_filter:
        print(f"Processing single project: '{project_name_filter}'")
    else:
        print(f"Processing all projects")
    
    print(f"Accessing projects for user '{SAST_username}'")
    
    access_token = SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url)
    if not access_token:
        error_message = f"Failed to obtain access token for user {SAST_username}."
        print(error_message)
        return ""
    
    projects_and_ids = []
    projects = SAST_get_projects(access_token=access_token, SAST_api_url=SAST_api_url)
    if not projects:
        error_message = f"Failed to obtain projects for user '{SAST_username}'."
        print(error_message)
        return ""

    # Filter projects if project_name_filter is specified
    if project_name_filter:
        projects = [p for p in projects if p['name'] == project_name_filter]
        if not projects:
            error_message = f"Project '{project_name_filter}' not found."
            print(error_message)
            return ""
        print(f"Found project '{project_name_filter}' (ID: {projects[0]['id']})")
    
    for project in projects:
        try:
            print(f"Project: {project['name']} (ID: {project['id']})")
        except UnicodeEncodeError:
            print(f"Project ID: {project['id']} (name contains non-ASCII characters)")
        projects_and_ids.append({project['name']: project['id']})
        
    project_name_and_scan_ids = {}
    
    for project in projects_and_ids:
        project_name, project_id = next(iter(project.items()))
        safe_print(f"Getting successful scans for project '{project_name}'")
        try:
            scans = SAST_get_scans(project_id=project_id, access_token=access_token, SAST_api_url=SAST_api_url)
            successful_scans = [scan for scan in scans if scan['status']['name'] == 'Finished']
            safe_print(f"Found {len(successful_scans)} successful scans for project '{project_name}'")
            
            scan_info = [{'id': scan['id'], 'dateAndTime': scan['dateAndTime']['startedOn']} for scan in successful_scans]
            if scan_info:  # Only add if there are scans
                project_name_and_scan_ids[project_name] = scan_info
        except Exception as e:
            safe_print(f"Error processing project '{project_name}': {e}")
            continue
        
    if not project_name_and_scan_ids:
        error_message = f"No projects with successful scans found for user '{SAST_username}'."
        print(error_message)
        return ""
    
    print(f"\nTotal projects with scans: {len(project_name_and_scan_ids)}")
    for project_name, scans in project_name_and_scan_ids.items():
        safe_print(f"{project_name}: {len(scans)} scans")
    
    if unlock_all:
        print("About to unlock all scans...")
        unlock_all_scans(access_token=access_token, SAST_api_url=SAST_api_url, project_name_and_scan_ids=project_name_and_scan_ids)
    else:
        print(f"About to lock scans {lock_interval} for each project...")
        lock_scans_by_interval(access_token=access_token, SAST_api_url=SAST_api_url, project_name_and_scan_ids=project_name_and_scan_ids, interval=lock_interval)
        
        # Trigger data retention if requested
        if run_data_retention and num_scans_to_keep is not None:
            print(f"\nTriggering data retention to keep {num_scans_to_keep} scans per project...")
            try:
                result = SAST_data_retention_by_scans(
                    access_token=access_token,
                    SAST_api_url=SAST_api_url,
                    num_scans_to_keep=num_scans_to_keep
                )
                print(f"Data retention completed successfully")
                if result:
                    print(f"Response: {result}")
            except Exception as e:
                print(f"Error during data retention: {str(e)}")



def unlock_all_scans(access_token, SAST_api_url, project_name_and_scan_ids):
    for project_name, scans in project_name_and_scan_ids.items():
        
        safe_print(f"Unlocking scans for project '{project_name}':")

        scan_ids = []
        for scan in scans:
            scan_ids.append(scan['id'])
        
        for scan_id in scan_ids:
            print(f"Unlocking scan with id '{scan_id}'")

            SAST_unlock_scan_by_id(access_token=access_token, SAST_api_url=SAST_api_url, scan_id=scan_id)
    print("Finished unlocking scans across all projects.")

def SAST_lock_scan_by_id(access_token, SAST_api_url, scan_id):
    url = f"{SAST_api_url}/sast/lockScan"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    payload = {
        'id': scan_id
    }
    proxies = get_proxies()
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.put(url=url, headers=headers, params=payload, proxies=proxies, verify=False)
            response.raise_for_status()
            
            # Add delay to avoid rate limiting
            time.sleep(REQUEST_DELAY)
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:  # Rate limit error
                if attempt < MAX_RETRIES - 1:
                    retry_delay = INITIAL_RETRY_DELAY * (RETRY_BACKOFF_FACTOR ** attempt)
                    print(f"Rate limit hit locking scan {scan_id}. Retrying in {retry_delay} seconds... (attempt {attempt + 1}/{MAX_RETRIES})")
                    time.sleep(retry_delay)
                else:
                    raise Exception(f"Failed after {MAX_RETRIES} retries: {e}")
            else:
                raise
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {e}")
    
    raise Exception(f"Failed to lock scan {scan_id} after {MAX_RETRIES} retries")

def SAST_unlock_scan_by_id(access_token, SAST_api_url, scan_id):
    url = f"{SAST_api_url}/sast/unLockScan"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    payload = {
        'id': scan_id
    }
    proxies = get_proxies()
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.put(url=url, headers=headers, params=payload, proxies=proxies, verify=False)
            response.raise_for_status()
            
            # Add delay to avoid rate limiting
            time.sleep(REQUEST_DELAY)
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:  # Rate limit error
                if attempt < MAX_RETRIES - 1:
                    retry_delay = INITIAL_RETRY_DELAY * (RETRY_BACKOFF_FACTOR ** attempt)
                    print(f"Rate limit hit unlocking scan {scan_id}. Retrying in {retry_delay} seconds... (attempt {attempt + 1}/{MAX_RETRIES})")
                    time.sleep(retry_delay)
                else:
                    raise Exception(f"Failed after {MAX_RETRIES} retries: {e}")
            else:
                raise
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {e}")
    
    raise Exception(f"Failed to unlock scan {scan_id} after {MAX_RETRIES} retries")


def SAST_data_retention_by_scans(access_token, SAST_api_url, num_scans_to_keep):
    """
    Trigger data retention in Checkmarx SAST to keep only the specified number of scans per project
    
    Args:
        access_token: Bearer token for authentication
        SAST_api_url: Base URL for SAST API
        num_scans_to_keep: Number of recent scans to keep per project
    
    Returns:
        Response from the API
    """
    url = f"{SAST_api_url}/help/sast/dataRetention/byNumberOfScans"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    payload = {
        'numOfSuccessfulScansToPreserve': num_scans_to_keep
    }
    proxies = get_proxies()
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(url=url, headers=headers, json=payload, proxies=proxies, verify=False)
            response.raise_for_status()
            
            # Add delay to avoid rate limiting
            time.sleep(REQUEST_DELAY)
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:  # Rate limit error
                if attempt < MAX_RETRIES - 1:
                    retry_delay = INITIAL_RETRY_DELAY * (RETRY_BACKOFF_FACTOR ** attempt)
                    print(f"Rate limit hit during data retention. Retrying in {retry_delay} seconds... (attempt {attempt + 1}/{MAX_RETRIES})")
                    time.sleep(retry_delay)
                else:
                    raise Exception(f"Failed after {MAX_RETRIES} retries: {e}")
            else:
                raise
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {e}")
    
    raise Exception(f"Failed to trigger data retention after {MAX_RETRIES} retries")


def lock_scans_by_interval(access_token, SAST_api_url, project_name_and_scan_ids, interval=90):
    for project_name, scans in project_name_and_scan_ids.items():
        safe_print(f"Processing project: {project_name}")
        
        sorted_scans = sorted(scans, key=lambda x: x['dateAndTime'])
        
        if not sorted_scans:
            safe_print(f"No scans found for project {project_name}")
            continue
        
        scans_to_lock = []
        try:
            current_interval_start = datetime.datetime.strptime(sorted_scans[0]['dateAndTime'], "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            current_interval_start = datetime.datetime.strptime(sorted_scans[0]['dateAndTime'], "%Y-%m-%dT%H:%M:%S")

        for scan in sorted_scans:
            try:
                scan_date = datetime.datetime.strptime(scan['dateAndTime'], "%Y-%m-%dT%H:%M:%S.%f")
            except ValueError:
                scan_date = datetime.datetime.strptime(scan['dateAndTime'], "%Y-%m-%dT%H:%M:%S")
                       
            if scan_date >= current_interval_start:
                scans_to_lock.append(scan)
                current_interval_start = scan_date + timedelta(days=interval)
                
        for scan in scans_to_lock:
            try:
                SAST_lock_scan_by_id(scan_id=scan['id'], access_token=access_token, SAST_api_url=SAST_api_url)
                safe_print(f"Locked scan {scan['id']} for project '{project_name}'")
            except Exception as e:
                safe_print(f"Failed to lock scan {scan['id']} for project '{project_name}': {str(e)}")

    print("Finished locking scans for all projects")
    
def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Checkmarx SAST Scan Lock/Unlock Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False  # Disable prefix matching
    )
    
    # Create mutually exclusive group for lock/unlock operations
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--lock', action='store_true', help='Lock scans based on the specified interval')
    action_group.add_argument('--unlockall', action='store_true', help='Unlock all scans across all projects')
    
    parser.add_argument('--interval_days', type=int, help='Number of days for the lock interval (required with --lock)')
    parser.add_argument('--project_name', type=str, help='Process only a specific project by name (optional, default: process all projects)')
    parser.add_argument('--run_data_retention', action='store_true', help='Run data retention after locking scans (only with --lock)')
    parser.add_argument('--keep_scans', type=int, help='Number of scans to keep per project during data retention (required with --run_data_retention)')

    
    args = parser.parse_args()
    
    # Validate that --interval_days is provided when --lock is used
    if args.lock and args.interval_days is None:
        parser.error('--interval_days is required when using --lock')
    
    # Validate that --run_data_retention is only used with --lock
    if args.run_data_retention and not args.lock:
        parser.error('--run_data_retention can only be used with --lock')
    
    # Validate that --keep_scans is provided when --run_data_retention is used
    if args.run_data_retention and args.keep_scans is None:
        parser.error('--keep_scans is required when using --run_data_retention')
    
    # Validate that --keep_scans is a positive number
    if args.keep_scans is not None and args.keep_scans <= 0:
        parser.error('--keep_scans must be a positive number')
    
    return args
           
            
def main():
    args = parse_arguments()

    # Display proxy status
    proxies = get_proxies()
    if proxies:
        print(f"Using proxy configuration: {proxies}")
    else:
        print("No proxy configured - connecting directly")
    
    if args.lock:
        interval = args.interval_days
        if args.project_name:
            print(f"Locking scans every {interval} days for project '{args.project_name}'...")
        else:
            print(f"Locking scans every {interval} days for each project...")
        
        # Show data retention info if requested
        if args.run_data_retention:
            print(f"Data retention will be triggered after locking to keep {args.keep_scans} scans per project")
        
        prepare_for_data_retention(
            unlock_all=False, 
            lock_interval=interval, 
            project_name_filter=args.project_name,
            run_data_retention=args.run_data_retention,
            num_scans_to_keep=args.keep_scans
        )
    elif args.unlockall:
        if args.project_name:
            print(f"Unlocking all scans for project '{args.project_name}'...")
        else:
            print("Unlocking all scans across all projects...")
        prepare_for_data_retention(unlock_all=True, project_name_filter=args.project_name)
    

if __name__ == '__main__':
    main()
